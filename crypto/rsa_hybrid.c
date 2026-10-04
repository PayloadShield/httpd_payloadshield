#include "aead_provider.h"

#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include <openssl/crypto.h>
#include <openssl/rsa.h>
#include <openssl/rand.h>

#define PAYLOADSHIELD_NONCE_SIZE 12
#define PAYLOADSHIELD_TAG_SIZE 16
#define PAYLOADSHIELD_RSA_AES_KEY_SIZE 32

typedef struct {
    const unsigned char *value;
    size_t length;
} payloadshield_json_string_t;

static void
payloadshield_skip_space(const unsigned char **cursor, const unsigned char *end)
{
    while (*cursor < end && (**cursor == ' ' || **cursor == '\t'
           || **cursor == '\r' || **cursor == '\n'))
    {
        (*cursor)++;
    }
}

static int
payloadshield_parse_string(const unsigned char **cursor, const unsigned char *end,
    payloadshield_json_string_t *value)
{
    const unsigned char *start;

    if (*cursor == end || *(*cursor)++ != '"') {
        return 0;
    }
    start = *cursor;
    while (*cursor < end && **cursor != '"') {
        if (**cursor == '\\') {
            if (*cursor + 1 == end || (*cursor)[1] != '/') {
                return 0;
            }
            (*cursor) += 2;
            continue;
        }
        if (**cursor < 0x20) {
            return 0;
        }
        (*cursor)++;
    }
    if (*cursor == end) {
        return 0;
    }
    value->value = start;
    value->length = (size_t) (*cursor - start);
    (*cursor)++;
    return 1;
}

static int
payloadshield_json_equal(const payloadshield_json_string_t *value,
    const char *expected)
{
    size_t length = strlen(expected);
    return value->length == length
           && memcmp(value->value, expected, length) == 0;
}

static int
payloadshield_parse_bundle(const unsigned char *json, size_t json_len,
    payloadshield_json_string_t *key, payloadshield_json_string_t *nonce,
    payloadshield_json_string_t *data)
{
    const unsigned char *cursor = json;
    const unsigned char *end = json + json_len;
    payloadshield_json_string_t name;
    payloadshield_json_string_t value;
    unsigned int found = 0;

    payloadshield_skip_space(&cursor, end);
    if (cursor == end || *cursor++ != '{') {
        return 0;
    }

    for (;;) {
        payloadshield_skip_space(&cursor, end);
        if (!payloadshield_parse_string(&cursor, end, &name)) {
            return 0;
        }
        payloadshield_skip_space(&cursor, end);
        if (cursor == end || *cursor++ != ':') {
            return 0;
        }
        payloadshield_skip_space(&cursor, end);
        if (!payloadshield_parse_string(&cursor, end, &value)) {
            return 0;
        }

        if (payloadshield_json_equal(&name, "key")) {
            if (found & 1) return 0;
            *key = value;
            found |= 1;
        } else if (payloadshield_json_equal(&name, "nonce")) {
            if (found & 2) return 0;
            *nonce = value;
            found |= 2;
        } else if (payloadshield_json_equal(&name, "data")) {
            if (found & 4) return 0;
            *data = value;
            found |= 4;
        } else {
            return 0;
        }

        payloadshield_skip_space(&cursor, end);
        if (cursor == end) {
            return 0;
        }
        if (*cursor == '}') {
            cursor++;
            break;
        }
        if (*cursor++ != ',') {
            return 0;
        }
    }

    payloadshield_skip_space(&cursor, end);
    return found == 7 && cursor == end;
}

static int
payloadshield_base64_encode(const unsigned char *input, size_t input_len,
    unsigned char **encoded, size_t *encoded_len)
{
    size_t capacity;
    unsigned char *result;
    int written;

    if (input_len > (size_t) INT_MAX / 4 * 3
        || input_len > (SIZE_MAX - 4) / 4 * 3)
    {
        return 0;
    }
    capacity = 4 * ((input_len + 2) / 3);
    if (capacity > SIZE_MAX - 1) {
        return 0;
    }
    result = OPENSSL_malloc(capacity + 1);
    if (result == NULL) {
        return 0;
    }
    written = EVP_EncodeBlock(result, input, (int) input_len);
    if (written < 0 || (size_t) written != capacity) {
        OPENSSL_free(result);
        return 0;
    }
    result[capacity] = '\0';
    *encoded = result;
    *encoded_len = capacity;
    return 1;
}

static int
payloadshield_base64_decode(const payloadshield_json_string_t *encoded,
    unsigned char **decoded, size_t *decoded_len)
{
    size_t i;
    size_t normalized_len = 0;
    size_t padding = 0;
    size_t capacity;
    size_t output_index;
    size_t input_len;
    const unsigned char *input;
    unsigned char *normalized = NULL;
    unsigned char *decoded_block;
    unsigned char *result;
    size_t result_len;
    int written;

    if (encoded->length == 0 || encoded->length > INT_MAX) {
        return 0;
    }
    for (i = 0; i < encoded->length; i++) {
        unsigned char c = encoded->value[i];
        if (c == '\\') {
            if (i + 1 == encoded->length || encoded->value[i + 1] != '/') {
                return 0;
            }
            i++;
        }
        normalized_len++;
    }
    if (normalized_len == 0 || normalized_len % 4 != 0) {
        return 0;
    }
    if (normalized_len != encoded->length) {
        normalized = OPENSSL_malloc(normalized_len);
        if (normalized == NULL) {
            return 0;
        }
        output_index = 0;
        for (i = 0; i < encoded->length; i++) {
            unsigned char c = encoded->value[i];
            if (c == '\\') i++;
            normalized[output_index++] = encoded->value[i];
        }
        input = normalized;
        input_len = normalized_len;
    } else {
        input = encoded->value;
        input_len = encoded->length;
    }

    for (i = 0; i < input_len; i++) {
        unsigned char c = input[i];
        int valid = (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z')
                    || (c >= '0' && c <= '9') || c == '+' || c == '/';
        if (c == '=') {
            if (i < input_len - 2) goto failed;
            padding++;
        } else if (!valid || padding != 0) {
            goto failed;
        }
    }
    if (padding > 2) goto failed;

    capacity = input_len / 4 * 3;
    decoded_block = OPENSSL_malloc(capacity == 0 ? 1 : capacity);
    if (decoded_block == NULL) goto failed;
    written = EVP_DecodeBlock(decoded_block, input, (int) input_len);
    if (written < 0 || (size_t) written < padding) {
        OPENSSL_clear_free(decoded_block, capacity == 0 ? 1 : capacity);
        goto failed;
    }
    result_len = (size_t) written - padding;
    result = OPENSSL_malloc(result_len == 0 ? 1 : result_len);
    if (result == NULL) {
        OPENSSL_clear_free(decoded_block, capacity == 0 ? 1 : capacity);
        goto failed;
    }
    if (result_len != 0) memcpy(result, decoded_block, result_len);
    OPENSSL_clear_free(decoded_block, capacity == 0 ? 1 : capacity);
    *decoded = result;
    *decoded_len = result_len;
    OPENSSL_clear_free(normalized, normalized_len);
    return 1;

failed:
    OPENSSL_clear_free(normalized, normalized_len);
    return 0;
}

static int
payloadshield_rsa_key_valid(EVP_PKEY *key)
{
    return key != NULL && EVP_PKEY_base_id(key) == EVP_PKEY_RSA
           && EVP_PKEY_get_bits(key) >= 2048;
}

static int
payloadshield_rsa_validate(const payloadshield_crypto_config_t *config,
    int encrypting)
{
    if (config == NULL) {
        return PAYLOADSHIELD_CRYPTO_INVALID;
    }
    if (encrypting) {
        return payloadshield_rsa_key_valid(config->public_key)
                   ? PAYLOADSHIELD_CRYPTO_OK : PAYLOADSHIELD_CRYPTO_INVALID;
    }
    return payloadshield_rsa_key_valid(config->private_key)
               ? PAYLOADSHIELD_CRYPTO_OK : PAYLOADSHIELD_CRYPTO_INVALID;
}

static int
payloadshield_rsa_setup(EVP_PKEY_CTX *ctx)
{
    return EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING) > 0
           && EVP_PKEY_CTX_set_rsa_oaep_md(ctx, EVP_sha256()) > 0
           && EVP_PKEY_CTX_set_rsa_mgf1_md(ctx, EVP_sha256()) > 0;
}

static int
payloadshield_rsa_encrypt(const payloadshield_crypto_config_t *config,
    const unsigned char *input, size_t input_len,
    payloadshield_buffer_t *output)
{
    EVP_PKEY_CTX *rsa_ctx = NULL;
    payloadshield_buffer_t encrypted = { NULL, 0 };
    unsigned char aes_key[PAYLOADSHIELD_RSA_AES_KEY_SIZE];
    unsigned char *wrapped_key = NULL;
    unsigned char *b64_key = NULL;
    unsigned char *b64_nonce = NULL;
    unsigned char *b64_data = NULL;
    unsigned char *json = NULL;
    unsigned char *result = NULL;
    size_t wrapped_key_len = 0;
    size_t b64_key_len = 0, b64_nonce_len = 0, b64_data_len = 0;
    size_t json_len = 0, result_len;
    int json_written;
    int status = PAYLOADSHIELD_CRYPTO_FAILURE;

    if (payloadshield_rsa_validate(config, 1) != PAYLOADSHIELD_CRYPTO_OK
        || (input == NULL && input_len != 0)
        || (config->max_payload_size != 0 && input_len > config->max_payload_size))
    {
        return PAYLOADSHIELD_CRYPTO_INVALID;
    }
    if (RAND_bytes(aes_key, sizeof(aes_key)) != 1) {
        goto done;
    }
    {
        payloadshield_crypto_config_t aead_config = *config;
        aead_config.key = aes_key;
        aead_config.key_len = sizeof(aes_key);
        status = payloadshield_aead_encrypt(EVP_aes_256_gcm(), &aead_config,
                                            input, input_len, &encrypted);
        if (status != PAYLOADSHIELD_CRYPTO_OK) {
            goto done;
        }
    }

    rsa_ctx = EVP_PKEY_CTX_new(config->public_key, NULL);
    if (rsa_ctx == NULL || EVP_PKEY_encrypt_init(rsa_ctx) <= 0
        || !payloadshield_rsa_setup(rsa_ctx)
        || EVP_PKEY_encrypt(rsa_ctx, NULL, &wrapped_key_len,
                            aes_key, sizeof(aes_key)) <= 0)
    {
        status = PAYLOADSHIELD_CRYPTO_FAILURE;
        goto done;
    }
    wrapped_key = OPENSSL_malloc(wrapped_key_len);
    if (wrapped_key == NULL) {
        status = PAYLOADSHIELD_CRYPTO_NOMEM;
        goto done;
    }
    if (EVP_PKEY_encrypt(rsa_ctx, wrapped_key, &wrapped_key_len,
                         aes_key, sizeof(aes_key)) <= 0
        || !payloadshield_base64_encode(wrapped_key, wrapped_key_len,
                                        &b64_key, &b64_key_len)
        || !payloadshield_base64_encode(encrypted.data,
                                        PAYLOADSHIELD_NONCE_SIZE,
                                        &b64_nonce, &b64_nonce_len)
        || !payloadshield_base64_encode(
               encrypted.data + PAYLOADSHIELD_NONCE_SIZE,
               encrypted.len - PAYLOADSHIELD_NONCE_SIZE,
               &b64_data, &b64_data_len))
    {
        status = PAYLOADSHIELD_CRYPTO_FAILURE;
        goto done;
    }

    if (b64_key_len > SIZE_MAX - b64_nonce_len
        || b64_key_len + b64_nonce_len > SIZE_MAX - b64_data_len
        || b64_key_len + b64_nonce_len + b64_data_len
            > SIZE_MAX - (sizeof("{\"key\":\"\",\"nonce\":\"\",\"data\":\"\"}") - 1) - 1)
    {
        status = PAYLOADSHIELD_CRYPTO_NOMEM;
        goto done;
    }
    json_len = b64_key_len + b64_nonce_len + b64_data_len
               + sizeof("{\"key\":\"\",\"nonce\":\"\",\"data\":\"\"}") - 1;
    json = OPENSSL_malloc(json_len + 1);
    if (json == NULL) {
        status = PAYLOADSHIELD_CRYPTO_NOMEM;
        goto done;
    }
    json_written = snprintf((char *) json, json_len + 1,
                            "{\"key\":\"%s\",\"nonce\":\"%s\",\"data\":\"%s\"}",
                            b64_key, b64_nonce, b64_data);
    if (json_written < 0 || (size_t) json_written != json_len)
    {
        status = PAYLOADSHIELD_CRYPTO_FAILURE;
        goto done;
    }
    if (!payloadshield_base64_encode(json, strlen((char *) json),
                                     &result, &result_len))
    {
        status = PAYLOADSHIELD_CRYPTO_NOMEM;
        goto done;
    }

    output->data = result;
    output->len = result_len;
    result = NULL;
    status = PAYLOADSHIELD_CRYPTO_OK;

done:
    EVP_PKEY_CTX_free(rsa_ctx);
    payloadshield_buffer_free(&encrypted);
    OPENSSL_cleanse(aes_key, sizeof(aes_key));
    OPENSSL_clear_free(wrapped_key, wrapped_key_len);
    OPENSSL_free(b64_key);
    OPENSSL_free(b64_nonce);
    OPENSSL_free(b64_data);
    OPENSSL_clear_free(json, json == NULL ? 0 : json_len + 1);
    OPENSSL_free(result);
    return status;
}

static int
payloadshield_rsa_decrypt(const payloadshield_crypto_config_t *config,
    const unsigned char *input, size_t input_len,
    payloadshield_buffer_t *output)
{
    EVP_PKEY_CTX *rsa_ctx = NULL;
    payloadshield_json_string_t outer, key_field, nonce_field, data_field;
    unsigned char *json = NULL;
    unsigned char *wrapped_key = NULL;
    unsigned char *nonce = NULL;
    unsigned char *data = NULL;
    unsigned char *aes_key = NULL;
    unsigned char *combined = NULL;
    size_t json_len = 0, wrapped_key_len = 0, nonce_len = 0, data_len = 0;
    size_t aes_key_len = 0, combined_len = 0;
    int status = PAYLOADSHIELD_CRYPTO_INVALID;

    if (payloadshield_rsa_validate(config, 0) != PAYLOADSHIELD_CRYPTO_OK
        || input == NULL || input_len == 0 || input_len > INT_MAX)
    {
        return PAYLOADSHIELD_CRYPTO_INVALID;
    }

    outer.value = input;
    outer.length = input_len;
    if (!payloadshield_base64_decode(&outer, &json, &json_len)
        || !payloadshield_parse_bundle(json, json_len, &key_field,
                                       &nonce_field, &data_field)
        || !payloadshield_base64_decode(&key_field, &wrapped_key,
                                       &wrapped_key_len)
        || !payloadshield_base64_decode(&nonce_field, &nonce, &nonce_len)
        || !payloadshield_base64_decode(&data_field, &data, &data_len))
    {
        goto done;
    }

    if (nonce_len != PAYLOADSHIELD_NONCE_SIZE || data_len < PAYLOADSHIELD_TAG_SIZE
        || wrapped_key_len != (size_t) EVP_PKEY_get_size(config->private_key)
        || data_len - PAYLOADSHIELD_TAG_SIZE > INT_MAX
        || (config->max_payload_size != 0
            && data_len - PAYLOADSHIELD_TAG_SIZE > config->max_payload_size))
    {
        goto done;
    }

    rsa_ctx = EVP_PKEY_CTX_new(config->private_key, NULL);
    if (rsa_ctx == NULL || EVP_PKEY_decrypt_init(rsa_ctx) <= 0
        || !payloadshield_rsa_setup(rsa_ctx)
        || EVP_PKEY_decrypt(rsa_ctx, NULL, &aes_key_len,
                            wrapped_key, wrapped_key_len) <= 0)
    {
        status = PAYLOADSHIELD_CRYPTO_FAILURE;
        goto done;
    }
    aes_key = OPENSSL_malloc(aes_key_len);
    if (aes_key == NULL) {
        status = PAYLOADSHIELD_CRYPTO_NOMEM;
        goto done;
    }
    if (EVP_PKEY_decrypt(rsa_ctx, aes_key, &aes_key_len,
                         wrapped_key, wrapped_key_len) <= 0
        || aes_key_len != PAYLOADSHIELD_RSA_AES_KEY_SIZE)
    {
        status = PAYLOADSHIELD_CRYPTO_FAILURE;
        goto done;
    }

    if (data_len > SIZE_MAX - nonce_len) {
        goto done;
    }
    combined_len = nonce_len + data_len;
    combined = OPENSSL_malloc(combined_len);
    if (combined == NULL) {
        status = PAYLOADSHIELD_CRYPTO_NOMEM;
        goto done;
    }
    memcpy(combined, nonce, nonce_len);
    memcpy(combined + nonce_len, data, data_len);
    {
        payloadshield_crypto_config_t aead_config = *config;
        aead_config.key = aes_key;
        aead_config.key_len = aes_key_len;
        status = payloadshield_aead_decrypt(EVP_aes_256_gcm(), &aead_config,
                                            combined, combined_len, output);
    }

done:
    EVP_PKEY_CTX_free(rsa_ctx);
    OPENSSL_clear_free(json, json_len);
    OPENSSL_clear_free(wrapped_key, wrapped_key_len);
    OPENSSL_clear_free(nonce, nonce_len);
    OPENSSL_clear_free(data, data_len);
    OPENSSL_clear_free(aes_key, aes_key_len);
    OPENSSL_clear_free(combined, combined_len);
    return status;
}

const payloadshield_crypto_provider_t payloadshield_rsa_hybrid_provider = {
    "rsa-hybrid",
    NULL,
    NULL,
    payloadshield_rsa_validate,
    payloadshield_rsa_encrypt,
    payloadshield_rsa_decrypt
};