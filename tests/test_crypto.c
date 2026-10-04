#include "payloadshield_crypto.h"
#include "payloadshield_envelope.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/evp.h>
#include <openssl/rsa.h>

static int failures;

#define CHECK(condition, label) \
    do { \
        if (!(condition)) { \
            fprintf(stderr, "FAIL: %s\n", label); \
            failures++; \
        } \
    } while (0)

static EVP_PKEY *
make_rsa_key(int bits)
{
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
    EVP_PKEY *key = NULL;

    if (ctx == NULL || EVP_PKEY_keygen_init(ctx) <= 0
        || EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, bits) <= 0
        || EVP_PKEY_keygen(ctx, &key) <= 0)
    {
        EVP_PKEY_free(key);
        key = NULL;
    }
    EVP_PKEY_CTX_free(ctx);
    return key;
}

static void
test_symmetric_provider(const char *name)
{
    static const unsigned char plaintext[] = "PayloadShield interoperability test";
    unsigned char key[32];
    unsigned char wrong_key[32];
    payloadshield_crypto_config_t config = { 0 };
    payloadshield_crypto_config_t wrong_config = { 0 };
    payloadshield_buffer_t encrypted = { 0 };
    payloadshield_buffer_t decrypted = { 0 };
    payloadshield_buffer_t rejected = { 0 };
    unsigned int i;
    int result;

    memset(key, 0x41, sizeof(key));
    memset(wrong_key, 0x42, sizeof(wrong_key));
    config.key = key;
    config.key_len = sizeof(key);
    config.max_payload_size = 1024;
    wrong_config = config;
    wrong_config.key = wrong_key;

    result = payloadshield_crypto_encrypt(name, &config, plaintext,
                                          sizeof(plaintext) - 1, &encrypted);
    CHECK(result == PAYLOADSHIELD_CRYPTO_OK, "symmetric encryption succeeds");
    CHECK(encrypted.len == sizeof(plaintext) - 1 + 28,
          "symmetric wire format is nonce || ciphertext || tag");
    if (result != PAYLOADSHIELD_CRYPTO_OK) {
        goto done;
    }

    result = payloadshield_crypto_decrypt(name, &config, encrypted.data,
                                          encrypted.len, &decrypted);
    CHECK(result == PAYLOADSHIELD_CRYPTO_OK, "symmetric decryption succeeds");
    CHECK(decrypted.len == sizeof(plaintext) - 1
          && memcmp(decrypted.data, plaintext, decrypted.len) == 0,
          "symmetric round-trip returns plaintext");
    payloadshield_buffer_free(&decrypted);

    for (i = 0; i < encrypted.len; i++) {
        unsigned char saved = encrypted.data[i];
        encrypted.data[i] ^= 1;
        result = payloadshield_crypto_decrypt(name, &config, encrypted.data,
                                              encrypted.len, &rejected);
        CHECK(result == PAYLOADSHIELD_CRYPTO_AUTH
              && rejected.data == NULL && rejected.len == 0,
              "modified nonce/ciphertext/tag rejected without plaintext");
        payloadshield_buffer_free(&rejected);
        encrypted.data[i] = saved;
        if (failures != 0) break;
    }

    result = payloadshield_crypto_decrypt(name, &wrong_config, encrypted.data,
                                          encrypted.len, &rejected);
    CHECK(result == PAYLOADSHIELD_CRYPTO_AUTH && rejected.data == NULL,
          "wrong symmetric key rejected");
    payloadshield_buffer_free(&rejected);

    result = payloadshield_crypto_decrypt(name, &config, encrypted.data,
                                          encrypted.len - 1, &rejected);
    CHECK(result == PAYLOADSHIELD_CRYPTO_AUTH
          && rejected.data == NULL,
          "truncated symmetric payload rejected");
    payloadshield_buffer_free(&rejected);

    config.max_payload_size = 4;
    result = payloadshield_crypto_encrypt(name, &config, plaintext,
                                          sizeof(plaintext) - 1, &rejected);
    CHECK(result == PAYLOADSHIELD_CRYPTO_INVALID,
          "oversized symmetric payload rejected");
    payloadshield_buffer_free(&rejected);

    config.max_payload_size = 1024;
    payloadshield_buffer_free(&encrypted);
    result = payloadshield_crypto_encrypt(name, &config, NULL, 0, &encrypted);
    CHECK(result == PAYLOADSHIELD_CRYPTO_OK, "empty plaintext encryption succeeds");
    if (result == PAYLOADSHIELD_CRYPTO_OK) {
        result = payloadshield_crypto_decrypt(name, &config, encrypted.data,
                                              encrypted.len, &decrypted);
        CHECK(result == PAYLOADSHIELD_CRYPTO_OK && decrypted.len == 0,
              "empty plaintext round-trip succeeds");
    }

done:
    payloadshield_buffer_free(&encrypted);
    payloadshield_buffer_free(&decrypted);
    payloadshield_buffer_free(&rejected);
}

static void
test_wire_interop(void)
{
    static const char wire[] = "{\"encrypted\":\"AAAAAAAAAAAAAAAAzqdAPU1ga24HTsXTuvOdGNDRyKeZmWvwJluYtdSKuRk=\"}";
    unsigned char key[32] = { 0 };
    payloadshield_crypto_config_t config = { 0 };
    payloadshield_buffer_t text = { 0 };
    payloadshield_buffer_t raw = { 0 };
    payloadshield_buffer_t plain = { 0 };
    unsigned char zeros[16] = { 0 };
    int result;

    config.key = key;
    config.key_len = sizeof(key);
    config.max_payload_size = 1024;
    result = payloadshield_envelope_unwrap((const unsigned char *) wire,
                                           sizeof(wire) - 1, &text);
    if (result == PAYLOADSHIELD_CRYPTO_OK) {
        result = payloadshield_base64_decode_buffer(text.data, text.len, &raw);
    }
    if (result == PAYLOADSHIELD_CRYPTO_OK) {
        result = payloadshield_crypto_decrypt("aes-gcm-256", &config,
                                              raw.data, raw.len, &plain);
    }
    CHECK(result == PAYLOADSHIELD_CRYPTO_OK && plain.len == sizeof(zeros)
          && memcmp(plain.data, zeros, sizeof(zeros)) == 0,
          "fixed Base64 envelope from reference vector decrypts");
    payloadshield_buffer_free(&text);
    payloadshield_buffer_free(&raw);
    payloadshield_buffer_free(&plain);
}

static void
test_aes_gcm_known_vector(void)
{
    static const unsigned char vector[] = {
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0xce, 0xa7, 0x40, 0x3d, 0x4d, 0x60, 0x6b, 0x6e,
        0x07, 0x4e, 0xc5, 0xd3, 0xba, 0xf3, 0x9d, 0x18,
        0xd0, 0xd1, 0xc8, 0xa7, 0x99, 0x99, 0x6b, 0xf0,
        0x26, 0x5b, 0x98, 0xb5, 0xd4, 0x8a, 0xb9, 0x19
    };
    static const unsigned char plaintext[16] = { 0 };
    unsigned char key[32] = { 0 };
    payloadshield_crypto_config_t config = { 0 };
    payloadshield_buffer_t output = { 0 };
    int result;

    config.key = key;
    config.key_len = sizeof(key);
    config.max_payload_size = sizeof(plaintext);
    result = payloadshield_crypto_decrypt("aes-gcm-256", &config,
        vector, sizeof(vector), &output);
    CHECK(result == PAYLOADSHIELD_CRYPTO_OK
          && output.len == sizeof(plaintext)
          && memcmp(output.data, plaintext, sizeof(plaintext)) == 0,
          "NIST AES-256-GCM deterministic vector decrypts");
    payloadshield_buffer_free(&output);
}

static void
test_provider_configuration_errors(void)
{
    payloadshield_crypto_config_t config = { 0 };
    EVP_PKEY *invalid_key = EVP_PKEY_new();

    CHECK(payloadshield_crypto_validate_config("aes-gcm-256", &config, 0)
              == PAYLOADSHIELD_CRYPTO_INVALID,
          "missing symmetric key rejected");
    config.public_key = invalid_key;
    config.private_key = invalid_key;
    CHECK(payloadshield_crypto_validate_config("rsa-hybrid", &config, 1)
              == PAYLOADSHIELD_CRYPTO_INVALID
          && payloadshield_crypto_validate_config("rsa-hybrid", &config, 0)
              == PAYLOADSHIELD_CRYPTO_INVALID,
          "invalid RSA key rejected");
    EVP_PKEY_free(invalid_key);
}

static void
test_payload_envelope(void)
{
    static const unsigned char request[] =
        " \r\n{ \"encrypted\" : \"YWJjL2RlZg==\" } \t";
    static const unsigned char malformed[] =
        "{\"encrypted\":\"YWJj\",\"extra\":true}";
    static const unsigned char escaped[] =
        "{\"encrypted\":\"YWJj\\/ZGVm\"}";
    payloadshield_buffer_t unwrapped = { 0 };
    payloadshield_buffer_t wrapped = { 0 };
    int result;

    result = payloadshield_envelope_unwrap(request, sizeof(request) - 1,
                                           &unwrapped);
    CHECK(result == PAYLOADSHIELD_CRYPTO_OK
          && unwrapped.len == sizeof("YWJjL2RlZg==") - 1
          && memcmp(unwrapped.data, "YWJjL2RlZg==", unwrapped.len) == 0,
          "existing encrypted JSON request envelope parsed");
    result = payloadshield_envelope_wrap(unwrapped.data, unwrapped.len, &wrapped);
    CHECK(result == PAYLOADSHIELD_CRYPTO_OK
          && wrapped.len == sizeof("{\"encrypted\":\"YWJjL2RlZg==\"}") - 1
          && memcmp(wrapped.data, "{\"encrypted\":\"YWJjL2RlZg==\"}",
                    wrapped.len) == 0,
          "existing encrypted JSON response envelope emitted");
    payloadshield_buffer_free(&unwrapped);
    payloadshield_buffer_free(&wrapped);

    result = payloadshield_envelope_unwrap(malformed, sizeof(malformed) - 1,
                                           &unwrapped);
    CHECK(result == PAYLOADSHIELD_CRYPTO_INVALID,
          "extra envelope properties rejected");

    result = payloadshield_envelope_unwrap(escaped, sizeof(escaped) - 1,
                                           &unwrapped);
    CHECK(result == PAYLOADSHIELD_CRYPTO_OK && unwrapped.len == 9
          && memcmp(unwrapped.data, "YWJj/ZGVm", 9) == 0,
          "JSON-escaped slash in encrypted value normalized");
    payloadshield_buffer_free(&unwrapped);
}

static void
test_rsa_hybrid(void)
{
    static const unsigned char plaintext[] = "Hybrid PayloadShield test";
    payloadshield_crypto_config_t config = { 0 };
    payloadshield_crypto_config_t wrong_config = { 0 };
    payloadshield_buffer_t encrypted = { 0 };
    payloadshield_buffer_t decrypted = { 0 };
    payloadshield_buffer_t rejected = { 0 };
    EVP_PKEY *key = make_rsa_key(2048);
    EVP_PKEY *wrong_key = make_rsa_key(2048);
    EVP_PKEY *small_key = make_rsa_key(1024);
    int result;

    CHECK(key != NULL && wrong_key != NULL && small_key != NULL,
          "RSA test keys generated");
    if (key == NULL || wrong_key == NULL || small_key == NULL) {
        goto done;
    }

    config.public_key = key;
    config.private_key = key;
    config.max_payload_size = 1024;
    result = payloadshield_crypto_encrypt("rsa-hybrid", &config, plaintext,
                                          sizeof(plaintext) - 1, &encrypted);
    CHECK(result == PAYLOADSHIELD_CRYPTO_OK, "RSA-Hybrid encryption succeeds");
    if (result != PAYLOADSHIELD_CRYPTO_OK) {
        goto done;
    }
    CHECK(encrypted.len > 0 && encrypted.data[0] != '{',
          "RSA-Hybrid wire value is Base64(JSON bundle)");

    result = payloadshield_crypto_decrypt("rsa-hybrid", &config, encrypted.data,
                                          encrypted.len, &decrypted);
    CHECK(result == PAYLOADSHIELD_CRYPTO_OK
          && decrypted.len == sizeof(plaintext) - 1
          && memcmp(decrypted.data, plaintext, decrypted.len) == 0,
          "RSA-Hybrid round-trip returns plaintext");
    payloadshield_buffer_free(&decrypted);

    encrypted.data[encrypted.len / 2] ^= 1;
    result = payloadshield_crypto_decrypt("rsa-hybrid", &config, encrypted.data,
                                          encrypted.len, &rejected);
    CHECK(result != PAYLOADSHIELD_CRYPTO_OK && rejected.data == NULL,
          "modified RSA-Hybrid bundle rejected");
    payloadshield_buffer_free(&rejected);
    encrypted.data[encrypted.len / 2] ^= 1;

    wrong_config = config;
    wrong_config.private_key = wrong_key;
    result = payloadshield_crypto_decrypt("rsa-hybrid", &wrong_config,
                                          encrypted.data, encrypted.len,
                                          &rejected);
    CHECK(result != PAYLOADSHIELD_CRYPTO_OK && rejected.data == NULL,
          "wrong RSA private key rejected");
    payloadshield_buffer_free(&rejected);

    wrong_config = config;
    wrong_config.public_key = small_key;
    result = payloadshield_crypto_encrypt("rsa-hybrid", &wrong_config,
                                          plaintext, sizeof(plaintext) - 1,
                                          &rejected);
    CHECK(result == PAYLOADSHIELD_CRYPTO_INVALID,
          "undersized RSA key rejected");
    payloadshield_buffer_free(&rejected);

    result = payloadshield_crypto_decrypt("rsa-hybrid", &config,
                                          (const unsigned char *) "not-base64!", 11,
                                          &rejected);
    CHECK(result == PAYLOADSHIELD_CRYPTO_INVALID,
          "malformed RSA-Hybrid envelope rejected");

done:
    EVP_PKEY_free(key);
    EVP_PKEY_free(wrong_key);
    EVP_PKEY_free(small_key);
    payloadshield_buffer_free(&encrypted);
    payloadshield_buffer_free(&decrypted);
    payloadshield_buffer_free(&rejected);
}

int
main(void)
{
    payloadshield_crypto_config_t config = { 0 };

    test_symmetric_provider("aes-gcm-256");
    test_symmetric_provider("chacha20-poly1305");
    test_aes_gcm_known_vector();
    test_wire_interop();
    test_provider_configuration_errors();
    test_rsa_hybrid();
    test_payload_envelope();
    CHECK(payloadshield_crypto_encrypt("unsupported", &config, NULL, 0,
                                      &(payloadshield_buffer_t) { 0 })
              == PAYLOADSHIELD_CRYPTO_UNSUPPORTED,
          "unsupported algorithm rejected");

    if (failures != 0) {
        fprintf(stderr, "%d crypto test(s) failed\n", failures);
        return EXIT_FAILURE;
    }
    puts("All crypto provider tests passed");
    return EXIT_SUCCESS;
}