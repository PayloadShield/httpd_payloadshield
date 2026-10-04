#include "httpd.h"
#include "http_config.h"
#include "http_core.h"
#include "http_log.h"
#include "http_protocol.h"
#include "http_request.h"
#include "util_filter.h"
#include "apr_strings.h"
#include "apr_buckets.h"
#include "apr_lib.h"

#include <limits.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/bio.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/pem.h>

#include "payloadshield_crypto.h"
#include "payloadshield_envelope.h"

#define PS_DEFAULT_MAX_BODY (10 * 1024 * 1024)
#define PS_MAX_KEY_FILE (1024 * 1024)

APLOG_USE_MODULE(payloadshield);

typedef struct {
    int enable;
    int fail_open;
    apr_int64_t max_body;
    const char *algorithm;
    unsigned char *key;
    size_t key_len;
    EVP_PKEY *private_key;
    EVP_PKEY *public_key;
} ps_conf;

typedef struct {
    unsigned char *data;
    size_t len;
    size_t cap;
} ps_buf;

typedef struct {
    unsigned char *data;
    size_t len;
} ps_secret;

typedef struct {
    apr_bucket_brigade *bb;
} ps_in_ctx;

typedef struct {
    ps_buf buf;
} ps_out_ctx;

static ap_filter_rec_t *ps_in_filter_rec;
static ap_filter_rec_t *ps_out_filter_rec;

/* ---------- helpers ---------- */

static void
ps_buf_free(ps_buf *b)
{
    if (b->data != NULL) {
        OPENSSL_cleanse(b->data, b->cap);
        free(b->data);
    }
    b->data = NULL;
    b->len = b->cap = 0;
}

/* Returns 0, -1 when over limit, -2 on allocation failure. */
static int
ps_buf_append(ps_buf *b, const void *src, size_t n, size_t limit)
{
    size_t needed;

    if (n > limit - b->len) {
        return -1;
    }
    needed = b->len + n;
    if (needed > b->cap) {
        size_t cap = b->cap == 0 ? (limit < 4096 ? limit : 4096) : b->cap;
        unsigned char *grown;

        if (cap == 0) cap = 1;
        while (cap < needed) {
            if (cap > limit / 2) {
                cap = limit;
                break;
            }
            cap *= 2;
        }
        grown = malloc(cap);
        if (grown == NULL) {
            return -2;
        }
        if (b->len != 0) {
            memcpy(grown, b->data, b->len);
        }
        if (b->data != NULL) {
            OPENSSL_cleanse(b->data, b->cap);
            free(b->data);
        }
        b->data = grown;
        b->cap = cap;
    }
    if (n != 0) {
        memcpy(b->data + b->len, src, n);
    }
    b->len = needed;
    return 0;
}

static apr_status_t
ps_cleanse_secret(void *data)
{
    ps_secret *s = data;
    OPENSSL_cleanse(s->data, s->len);
    return APR_SUCCESS;
}

static apr_status_t
ps_free_pkey(void *data)
{
    EVP_PKEY_free(data);
    return APR_SUCCESS;
}

static int
ps_is_rsa(const ps_conf *conf)
{
    return strcmp(conf->algorithm, "rsa-hybrid") == 0;
}

static int
ps_conf_ready(request_rec *r, const ps_conf *conf,
    payloadshield_crypto_config_t *cc, int encrypting)
{
    memset(cc, 0, sizeof(*cc));
    cc->key = conf->key;
    cc->key_len = conf->key_len;
    cc->private_key = conf->private_key;
    cc->public_key = conf->public_key;
    cc->max_payload_size = (size_t) (conf->max_body >= 0
                                     ? conf->max_body : PS_DEFAULT_MAX_BODY);
    if (conf->algorithm == NULL
        || payloadshield_crypto_validate_config(conf->algorithm, cc,
                                                encrypting)
           != PAYLOADSHIELD_CRYPTO_OK)
    {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                      "payloadshield algorithm or key configuration is invalid");
        return 0;
    }
    return 1;
}

/* ---------- configuration ---------- */

static void *
ps_create_dir_conf(apr_pool_t *p, char *dir)
{
    ps_conf *conf = apr_pcalloc(p, sizeof(*conf));

    (void) dir;
    conf->enable = -1;
    conf->fail_open = -1;
    conf->max_body = -1;
    return conf;
}

static void *
ps_merge_dir_conf(apr_pool_t *p, void *basev, void *addv)
{
    ps_conf *base = basev;
    ps_conf *add = addv;
    ps_conf *conf = apr_pcalloc(p, sizeof(*conf));

    conf->enable = add->enable != -1 ? add->enable : base->enable;
    conf->fail_open = add->fail_open != -1 ? add->fail_open : base->fail_open;
    conf->max_body = add->max_body >= 0 ? add->max_body : base->max_body;
    conf->algorithm = add->algorithm != NULL ? add->algorithm : base->algorithm;
    if (add->key != NULL) {
        conf->key = add->key;
        conf->key_len = add->key_len;
    } else {
        conf->key = base->key;
        conf->key_len = base->key_len;
    }
    conf->private_key = add->private_key != NULL ? add->private_key
                                                  : base->private_key;
    conf->public_key = add->public_key != NULL ? add->public_key
                                                : base->public_key;
    return conf;
}

/* Caller must cleanse and free *data. */
static int
ps_read_file(const char *path, unsigned char **data, size_t *length)
{
    BIO *bio = BIO_new_file(path, "rb");
    unsigned char *contents = NULL;
    size_t used = 0;
    unsigned char chunk[4096];
    int count;

    if (bio == NULL) {
        return 0;
    }
    while ((count = BIO_read(bio, chunk, sizeof(chunk))) > 0) {
        unsigned char *grown;

        if (used > PS_MAX_KEY_FILE - (size_t) count) {
            goto fail;
        }
        grown = malloc(used + (size_t) count);
        if (grown == NULL) {
            goto fail;
        }
        if (used != 0) {
            memcpy(grown, contents, used);
            OPENSSL_cleanse(contents, used);
            free(contents);
        }
        memcpy(grown + used, chunk, (size_t) count);
        contents = grown;
        used += (size_t) count;
    }
    BIO_free(bio);
    OPENSSL_cleanse(chunk, sizeof(chunk));
    if (count < 0 || used == 0) {
        if (contents != NULL) {
            OPENSSL_cleanse(contents, used);
            free(contents);
        }
        return 0;
    }
    *data = contents;
    *length = used;
    return 1;

fail:
    BIO_free(bio);
    OPENSSL_cleanse(chunk, sizeof(chunk));
    if (contents != NULL) {
        OPENSSL_cleanse(contents, used);
        free(contents);
    }
    return 0;
}

static const char *
ps_set_algorithm(cmd_parms *cmd, void *dconf, const char *arg)
{
    ps_conf *conf = dconf;

    if (payloadshield_crypto_provider(arg) == NULL) {
        return "PayloadShieldAlgorithm: unsupported algorithm "
               "(use aes-gcm-256, chacha20-poly1305 or rsa-hybrid)";
    }
    conf->algorithm = apr_pstrdup(cmd->pool, arg);
    return NULL;
}

static const char *
ps_set_key(cmd_parms *cmd, void *dconf, const char *arg)
{
    ps_conf *conf = dconf;
    unsigned char *raw = NULL;
    size_t raw_len = 0;
    size_t start = 0;
    size_t end;
    payloadshield_buffer_t decoded = { NULL, 0 };
    ps_secret *secret;
    const char *path = ap_server_root_relative(cmd->pool, arg);

    if (path == NULL || !ps_read_file(path, &raw, &raw_len)) {
        return "PayloadShieldKey: cannot read key file";
    }

    secret = apr_palloc(cmd->pool, sizeof(*secret));
    secret->data = apr_palloc(cmd->pool, 32);
    secret->len = 32;

    if (raw_len == 32) {
        memcpy(secret->data, raw, 32);
    } else {
        end = raw_len;
        while (start < end && apr_isspace(raw[start])) start++;
        while (end > start && apr_isspace(raw[end - 1])) end--;
        if (payloadshield_base64_decode_buffer(raw + start, end - start,
                                               &decoded)
                != PAYLOADSHIELD_CRYPTO_OK
            || decoded.len != 32)
        {
            payloadshield_buffer_free(&decoded);
            OPENSSL_cleanse(raw, raw_len);
            free(raw);
            return "PayloadShieldKey: key must be 32 raw bytes or Base64 of 32 bytes";
        }
        memcpy(secret->data, decoded.data, 32);
        OPENSSL_cleanse(decoded.data, decoded.len);
        payloadshield_buffer_free(&decoded);
    }
    OPENSSL_cleanse(raw, raw_len);
    free(raw);

    apr_pool_cleanup_register(cmd->pool, secret, ps_cleanse_secret,
                              apr_pool_cleanup_null);
    conf->key = secret->data;
    conf->key_len = 32;
    return NULL;
}

static const char *
ps_set_pkey(cmd_parms *cmd, void *dconf, const char *arg, int is_private)
{
    ps_conf *conf = dconf;
    const char *path = ap_server_root_relative(cmd->pool, arg);
    BIO *bio = path != NULL ? BIO_new_file(path, "rb") : NULL;
    EVP_PKEY *pkey;

    if (bio == NULL) {
        return "cannot read RSA key file";
    }
    pkey = is_private ? PEM_read_bio_PrivateKey(bio, NULL, NULL, NULL)
                      : PEM_read_bio_PUBKEY(bio, NULL, NULL, NULL);
    BIO_free(bio);
    if (pkey == NULL) {
        return "cannot parse RSA PEM key";
    }
    apr_pool_cleanup_register(cmd->pool, pkey, ps_free_pkey,
                              apr_pool_cleanup_null);
    if (is_private) {
        conf->private_key = pkey;
    } else {
        conf->public_key = pkey;
    }
    return NULL;
}

static const char *
ps_set_private_key(cmd_parms *cmd, void *dconf, const char *arg)
{
    return ps_set_pkey(cmd, dconf, arg, 1);
}

static const char *
ps_set_public_key(cmd_parms *cmd, void *dconf, const char *arg)
{
    return ps_set_pkey(cmd, dconf, arg, 0);
}

static const char *
ps_set_max_body(cmd_parms *cmd, void *dconf, const char *arg)
{
    ps_conf *conf = dconf;
    apr_off_t value;
    char *end;

    (void) cmd;
    if (apr_strtoff(&value, arg, &end, 10) != APR_SUCCESS || *end != '\0'
        || value <= 0)
    {
        return "PayloadShieldMaxBodySize must be a positive number of bytes";
    }
    conf->max_body = value;
    return NULL;
}

static const command_rec ps_commands[] = {
    AP_INIT_FLAG("PayloadShield", ap_set_flag_slot,
                 (void *) APR_OFFSETOF(ps_conf, enable),
                 RSRC_CONF | ACCESS_CONF,
                 "Enable PayloadShield request/response processing"),
    AP_INIT_TAKE1("PayloadShieldAlgorithm", ps_set_algorithm,
                  NULL, RSRC_CONF | ACCESS_CONF,
                  "aes-gcm-256, chacha20-poly1305 or rsa-hybrid"),
    AP_INIT_TAKE1("PayloadShieldKey", ps_set_key, NULL,
                  RSRC_CONF | ACCESS_CONF,
                  "Symmetric key file (32 raw bytes or Base64 of 32 bytes)"),
    AP_INIT_TAKE1("PayloadShieldPrivateKey", ps_set_private_key, NULL,
                  RSRC_CONF | ACCESS_CONF,
                  "RSA private key PEM used to decrypt requests"),
    AP_INIT_TAKE1("PayloadShieldPublicKey", ps_set_public_key, NULL,
                  RSRC_CONF | ACCESS_CONF,
                  "RSA public key PEM used to encrypt responses"),
    AP_INIT_TAKE1("PayloadShieldMaxBodySize", ps_set_max_body, NULL,
                  RSRC_CONF | ACCESS_CONF,
                  "Maximum plaintext request/response size in bytes"),
    AP_INIT_FLAG("PayloadShieldFailOpen", ap_set_flag_slot,
                 (void *) APR_OFFSETOF(ps_conf, fail_open),
                 RSRC_CONF | ACCESS_CONF,
                 "Pass data through unchanged when PayloadShield fails"),
    { NULL }
};

/* ---------- request: decrypt in fixups, replay through an input filter ---------- */

static apr_status_t
ps_in_filter(ap_filter_t *f, apr_bucket_brigade *bb, ap_input_mode_t mode,
    apr_read_type_e block, apr_off_t readbytes)
{
    ps_in_ctx *ctx = f->ctx;
    apr_bucket *e;
    apr_bucket *b;
    apr_status_t rv;

    (void) block;
    if (mode == AP_MODE_INIT) {
        return APR_SUCCESS;
    }
    if (mode != AP_MODE_READBYTES) {
        return APR_ENOTIMPL;
    }
    if (APR_BRIGADE_EMPTY(ctx->bb)) {
        APR_BRIGADE_INSERT_TAIL(bb,
            apr_bucket_eos_create(f->c->bucket_alloc));
        return APR_SUCCESS;
    }
    if (readbytes <= 0) {
        readbytes = APR_INT64_MAX;
    }
    rv = apr_brigade_partition(ctx->bb, readbytes, &e);
    if (rv != APR_SUCCESS && rv != APR_INCOMPLETE) {
        return rv;
    }
    while ((b = APR_BRIGADE_FIRST(ctx->bb)) != e) {
        APR_BUCKET_REMOVE(b);
        APR_BRIGADE_INSERT_TAIL(bb, b);
    }
    return APR_SUCCESS;
}

static int
ps_fixups(request_rec *r)
{
    ps_conf *conf = ap_get_module_config(r->per_dir_config,
                                         &payloadshield_module);
    payloadshield_crypto_config_t cc;
    ps_buf in = { NULL, 0, 0 };
    payloadshield_buffer_t encoded = { NULL, 0 };
    payloadshield_buffer_t plain = { NULL, 0 };
    apr_bucket_brigade *tmp;
    apr_bucket_brigade *replay;
    ps_in_ctx *ctx;
    ps_secret *secret;
    const unsigned char *out_data;
    size_t out_len;
    const char *cl;
    size_t max_body;
    size_t limit;
    int eos = 0;
    int rc;
    int decrypted = 0;
    int status = OK;

    if (conf->enable <= 0 || r->main != NULL || r->prev != NULL) {
        return DECLINED;
    }
    cl = apr_table_get(r->headers_in, "Content-Length");
    if (!(cl != NULL && apr_atoi64(cl) > 0)
        && apr_table_get(r->headers_in, "Transfer-Encoding") == NULL)
    {
        return DECLINED;
    }
    if (!ps_conf_ready(r, conf, &cc, 0)) {
        return HTTP_INTERNAL_SERVER_ERROR;
    }

    max_body = cc.max_payload_size;
    if (max_body > (SIZE_MAX - 32768) / 2) {
        return HTTP_REQUEST_ENTITY_TOO_LARGE;
    }
    limit = max_body * 2 + 32768;

    tmp = apr_brigade_create(r->pool, r->connection->bucket_alloc);
    while (!eos) {
        apr_bucket *b;
        apr_status_t rv = ap_get_brigade(r->input_filters, tmp,
                                         AP_MODE_READBYTES, APR_BLOCK_READ,
                                         HUGE_STRING_LEN);
        if (rv != APR_SUCCESS) {
            status = ap_map_http_request_error(rv, HTTP_BAD_REQUEST);
            goto done;
        }
        for (b = APR_BRIGADE_FIRST(tmp); b != APR_BRIGADE_SENTINEL(tmp);
             b = APR_BUCKET_NEXT(b))
        {
            const char *data;
            apr_size_t len;

            if (APR_BUCKET_IS_EOS(b)) {
                eos = 1;
                break;
            }
            if (APR_BUCKET_IS_METADATA(b)) {
                continue;
            }
            rv = apr_bucket_read(b, &data, &len, APR_BLOCK_READ);
            if (rv != APR_SUCCESS) {
                status = HTTP_BAD_REQUEST;
                goto done;
            }
            rc = ps_buf_append(&in, data, len, limit);
            if (rc != 0) {
                status = rc == -1 ? HTTP_REQUEST_ENTITY_TOO_LARGE
                                  : HTTP_INTERNAL_SERVER_ERROR;
                goto done;
            }
        }
        apr_brigade_cleanup(tmp);
    }

    rc = payloadshield_envelope_unwrap(in.data, in.len, &encoded);
    if (rc == PAYLOADSHIELD_CRYPTO_OK && !ps_is_rsa(conf)) {
        payloadshield_buffer_t text = encoded;
        rc = payloadshield_base64_decode_buffer(text.data, text.len, &encoded);
        payloadshield_buffer_free(&text);
    }
    if (rc == PAYLOADSHIELD_CRYPTO_OK) {
        rc = payloadshield_crypto_decrypt(conf->algorithm, &cc, encoded.data,
                                          encoded.len, &plain);
    }
    payloadshield_buffer_free(&encoded);

    if (rc == PAYLOADSHIELD_CRYPTO_OK && plain.len > max_body) {
        status = HTTP_REQUEST_ENTITY_TOO_LARGE;
        goto done;
    }
    if (rc == PAYLOADSHIELD_CRYPTO_OK) {
        out_data = plain.data;
        out_len = plain.len;
        decrypted = 1;
    } else if (conf->fail_open > 0 && rc != PAYLOADSHIELD_CRYPTO_NOMEM) {
        out_data = in.data;
        out_len = in.len;
    } else {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                      "payloadshield request decryption failed");
        status = rc == PAYLOADSHIELD_CRYPTO_NOMEM ? HTTP_INTERNAL_SERVER_ERROR
                                                   : HTTP_BAD_REQUEST;
        goto done;
    }

    secret = apr_palloc(r->pool, sizeof(*secret));
    secret->len = out_len;
    secret->data = apr_palloc(r->pool, out_len == 0 ? 1 : out_len);
    if (out_len != 0) {
        memcpy(secret->data, out_data, out_len);
    }
    apr_pool_cleanup_register(r->pool, secret, ps_cleanse_secret,
                              apr_pool_cleanup_null);

    replay = apr_brigade_create(r->pool, r->connection->bucket_alloc);
    if (out_len != 0) {
        APR_BRIGADE_INSERT_TAIL(replay,
            apr_bucket_immortal_create((const char *) secret->data, out_len,
                                       r->connection->bucket_alloc));
    }
    APR_BRIGADE_INSERT_TAIL(replay,
        apr_bucket_eos_create(r->connection->bucket_alloc));
    ctx = apr_palloc(r->pool, sizeof(*ctx));
    ctx->bb = replay;

    if (decrypted) {
        apr_table_unset(r->headers_in, "Transfer-Encoding");
        apr_table_setn(r->headers_in, "Content-Length",
                       apr_psprintf(r->pool, "%" APR_SIZE_T_FMT, out_len));
    }
    ap_add_input_filter_handle(ps_in_filter_rec, ctx, r, r->connection);

done:
    payloadshield_buffer_free(&plain);
    ps_buf_free(&in);
    return status == OK ? DECLINED : status;
}

/* ---------- response: buffer, encrypt, wrap ---------- */

static apr_status_t
ps_out_fail(ap_filter_t *f, apr_bucket_brigade *bb)
{
    request_rec *r = f->r;
    apr_bucket *e;

    apr_brigade_cleanup(bb);
    e = ap_bucket_error_create(HTTP_INTERNAL_SERVER_ERROR, NULL, r->pool,
                               f->c->bucket_alloc);
    APR_BRIGADE_INSERT_TAIL(bb, e);
    APR_BRIGADE_INSERT_TAIL(bb, apr_bucket_eos_create(f->c->bucket_alloc));
    ap_remove_output_filter(f);
    return ap_pass_brigade(f->next, bb);
}

static apr_status_t
ps_out_filter(ap_filter_t *f, apr_bucket_brigade *bb)
{
    request_rec *r = f->r;
    ps_conf *conf = ap_get_module_config(r->per_dir_config,
                                         &payloadshield_module);
    ps_out_ctx *ctx = f->ctx;
    payloadshield_crypto_config_t cc;
    payloadshield_buffer_t encrypted = { NULL, 0 };
    payloadshield_buffer_t envelope = { NULL, 0 };
    apr_bucket_brigade *out;
    const unsigned char *out_data;
    size_t out_len;
    apr_bucket *b;
    int eos = 0;
    int rc;

    if (ctx == NULL) {
        const char *ce;

        if (r->header_only || r->status == HTTP_NO_CONTENT
            || r->status == HTTP_NOT_MODIFIED
            || (r->status >= 100 && r->status < 200))
        {
            ap_remove_output_filter(f);
            return ap_pass_brigade(f->next, bb);
        }
        ce = apr_table_get(r->headers_out, "Content-Encoding");
        if (ce == NULL) ce = r->content_encoding;
        if (ce != NULL && *ce != '\0' && strcasecmp(ce, "identity") != 0) {
            if (conf->fail_open > 0) {
                ap_remove_output_filter(f);
                return ap_pass_brigade(f->next, bb);
            }
            ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                          "payloadshield refuses a Content-Encoding response");
            return ps_out_fail(f, bb);
        }
        if (!ps_conf_ready(r, conf, &cc, 1)) {
            return ps_out_fail(f, bb);
        }
        ctx = f->ctx = apr_pcalloc(r->pool, sizeof(*ctx));
    }

    for (b = APR_BRIGADE_FIRST(bb); b != APR_BRIGADE_SENTINEL(bb);
         b = APR_BUCKET_NEXT(b))
    {
        const char *data;
        apr_size_t len;
        apr_status_t rv;
        size_t max_body = (size_t) (conf->max_body >= 0
                                    ? conf->max_body : PS_DEFAULT_MAX_BODY);

        if (APR_BUCKET_IS_EOS(b)) {
            eos = 1;
            break;
        }
        if (APR_BUCKET_IS_METADATA(b)) {
            continue;
        }
        rv = apr_bucket_read(b, &data, &len, APR_BLOCK_READ);
        if (rv != APR_SUCCESS) {
            ps_buf_free(&ctx->buf);
            return ps_out_fail(f, bb);
        }
        if (ps_buf_append(&ctx->buf, data, len, max_body) != 0) {
            ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                          "payloadshield response buffering failed");
            ps_buf_free(&ctx->buf);
            return ps_out_fail(f, bb);
        }
    }
    apr_brigade_cleanup(bb);
    if (!eos) {
        return APR_SUCCESS;
    }

    ps_conf_ready(r, conf, &cc, 1);
    rc = payloadshield_crypto_encrypt(conf->algorithm, &cc, ctx->buf.data,
                                      ctx->buf.len, &encrypted);
    if (rc == PAYLOADSHIELD_CRYPTO_OK && !ps_is_rsa(conf)) {
        payloadshield_buffer_t raw = encrypted;
        rc = payloadshield_base64_encode_buffer(raw.data, raw.len, &encrypted);
        payloadshield_buffer_free(&raw);
    }
    if (rc == PAYLOADSHIELD_CRYPTO_OK) {
        rc = payloadshield_envelope_wrap(encrypted.data, encrypted.len,
                                         &envelope);
    }
    payloadshield_buffer_free(&encrypted);

    if (rc == PAYLOADSHIELD_CRYPTO_OK) {
        out_data = envelope.data;
        out_len = envelope.len;
        ap_set_content_type(r, "application/json");
        apr_table_unset(r->headers_out, "Content-MD5");
    } else if (conf->fail_open > 0) {
        out_data = ctx->buf.data;
        out_len = ctx->buf.len;
    } else {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                      "payloadshield response encryption failed");
        ps_buf_free(&ctx->buf);
        return ps_out_fail(f, bb);
    }

    out = apr_brigade_create(r->pool, f->c->bucket_alloc);
    {
        apr_status_t rv = apr_brigade_write(out, NULL, NULL,
                                            (const char *) out_data, out_len);
        payloadshield_buffer_free(&envelope);
        ps_buf_free(&ctx->buf);
        if (rv != APR_SUCCESS) {
            return ps_out_fail(f, bb);
        }
    }
    apr_table_unset(r->headers_out, "Content-Length");
    ap_set_content_length(r, (apr_off_t) out_len);
    APR_BRIGADE_INSERT_TAIL(out, apr_bucket_eos_create(f->c->bucket_alloc));
    ap_remove_output_filter(f);
    return ap_pass_brigade(f->next, out);
}

static void
ps_insert_filter(request_rec *r)
{
    ps_conf *conf = ap_get_module_config(r->per_dir_config,
                                         &payloadshield_module);

    if (conf->enable > 0 && r->main == NULL) {
        ap_add_output_filter_handle(ps_out_filter_rec, NULL, r, r->connection);
    }
}

static void
ps_register_hooks(apr_pool_t *p)
{
    (void) p;
    ps_in_filter_rec = ap_register_input_filter("PAYLOADSHIELD_IN",
        ps_in_filter, NULL, AP_FTYPE_RESOURCE);
    ps_out_filter_rec = ap_register_output_filter("PAYLOADSHIELD_OUT",
        ps_out_filter, NULL, AP_FTYPE_RESOURCE);
    ap_hook_fixups(ps_fixups, NULL, NULL, APR_HOOK_FIRST);
    ap_hook_insert_filter(ps_insert_filter, NULL, NULL, APR_HOOK_MIDDLE);
}

module AP_MODULE_DECLARE_DATA payloadshield_module = {
    STANDARD20_MODULE_STUFF,
    ps_create_dir_conf,
    ps_merge_dir_conf,
    NULL,
    NULL,
    ps_commands,
    ps_register_hooks
};
