#ifndef PAYLOADSHIELD_CRYPTO_H
#define PAYLOADSHIELD_CRYPTO_H

#include <stddef.h>

#include <openssl/evp.h>

typedef struct payloadshield_crypto_config_s payloadshield_crypto_config_t;
typedef struct payloadshield_crypto_provider_s payloadshield_crypto_provider_t;

typedef struct {
    unsigned char *data;
    size_t len;
} payloadshield_buffer_t;

struct payloadshield_crypto_config_s {
    const unsigned char *key;
    size_t key_len;
    EVP_PKEY *private_key;
    EVP_PKEY *public_key;
    size_t max_payload_size;
};

struct payloadshield_crypto_provider_s {
    const char *name;
    int (*init)(const payloadshield_crypto_config_t *config);
    void (*cleanup)(void);
    int (*validate_config)(const payloadshield_crypto_config_t *config,
        int encrypting);
    int (*encrypt)(const payloadshield_crypto_config_t *config,
        const unsigned char *input, size_t input_len,
        payloadshield_buffer_t *output);
    int (*decrypt)(const payloadshield_crypto_config_t *config,
        const unsigned char *input, size_t input_len,
        payloadshield_buffer_t *output);
};

enum {
    PAYLOADSHIELD_CRYPTO_OK = 0,
    PAYLOADSHIELD_CRYPTO_INVALID = -1,
    PAYLOADSHIELD_CRYPTO_NOMEM = -2,
    PAYLOADSHIELD_CRYPTO_AUTH = -3,
    PAYLOADSHIELD_CRYPTO_UNSUPPORTED = -4,
    PAYLOADSHIELD_CRYPTO_FAILURE = -5
};

int payloadshield_crypto_register(const payloadshield_crypto_provider_t *provider);
const payloadshield_crypto_provider_t *payloadshield_crypto_provider(const char *name);
int payloadshield_crypto_validate_config(const char *name,
    const payloadshield_crypto_config_t *config, int encrypting);
int payloadshield_crypto_init(const char *name,
    const payloadshield_crypto_config_t *config);
void payloadshield_crypto_cleanup(const char *name);
int payloadshield_crypto_encrypt(const char *name,
    const payloadshield_crypto_config_t *config,
    const unsigned char *input, size_t input_len,
    payloadshield_buffer_t *output);
int payloadshield_crypto_decrypt(const char *name,
    const payloadshield_crypto_config_t *config,
    const unsigned char *input, size_t input_len,
    payloadshield_buffer_t *output);
void payloadshield_buffer_free(payloadshield_buffer_t *buffer);

#endif