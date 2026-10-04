#include "payloadshield_crypto.h"

#include <string.h>

#include <openssl/crypto.h>

#define PAYLOADSHIELD_MAX_PROVIDERS 32

static const payloadshield_crypto_provider_t *providers[PAYLOADSHIELD_MAX_PROVIDERS];
static size_t provider_count;

int payloadshield_crypto_register_builtins(void);

int
payloadshield_crypto_register(const payloadshield_crypto_provider_t *provider)
{
    size_t i;

    if (provider == NULL || provider->name == NULL || provider->encrypt == NULL
        || provider->decrypt == NULL || provider->validate_config == NULL)
    {
        return PAYLOADSHIELD_CRYPTO_INVALID;
    }

    for (i = 0; i < provider_count; i++) {
        if (strcmp(providers[i]->name, provider->name) == 0) {
            return PAYLOADSHIELD_CRYPTO_INVALID;
        }
    }

    if (provider_count == PAYLOADSHIELD_MAX_PROVIDERS) {
        return PAYLOADSHIELD_CRYPTO_NOMEM;
    }

    providers[provider_count++] = provider;
    return PAYLOADSHIELD_CRYPTO_OK;
}

const payloadshield_crypto_provider_t *
payloadshield_crypto_provider(const char *name)
{
    size_t i;

    if (payloadshield_crypto_register_builtins() != PAYLOADSHIELD_CRYPTO_OK) {
        return NULL;
    }
    if (name == NULL) {
        return NULL;
    }

    for (i = 0; i < provider_count; i++) {
        if (strcmp(providers[i]->name, name) == 0) {
            return providers[i];
        }
    }

    return NULL;
}

int
payloadshield_crypto_validate_config(const char *name,
    const payloadshield_crypto_config_t *config, int encrypting)
{
    const payloadshield_crypto_provider_t *provider;

    provider = payloadshield_crypto_provider(name);
    if (provider == NULL) {
        return PAYLOADSHIELD_CRYPTO_UNSUPPORTED;
    }

    return provider->validate_config(config, encrypting);
}

int
payloadshield_crypto_init(const char *name,
    const payloadshield_crypto_config_t *config)
{
    const payloadshield_crypto_provider_t *provider;

    provider = payloadshield_crypto_provider(name);
    if (provider == NULL) {
        return PAYLOADSHIELD_CRYPTO_UNSUPPORTED;
    }

    return provider->init == NULL ? PAYLOADSHIELD_CRYPTO_OK
                                  : provider->init(config);
}

void
payloadshield_crypto_cleanup(const char *name)
{
    const payloadshield_crypto_provider_t *provider;

    provider = payloadshield_crypto_provider(name);
    if (provider != NULL && provider->cleanup != NULL) {
        provider->cleanup();
    }
}

int
payloadshield_crypto_encrypt(const char *name,
    const payloadshield_crypto_config_t *config,
    const unsigned char *input, size_t input_len,
    payloadshield_buffer_t *output)
{
    const payloadshield_crypto_provider_t *provider;
    int status;

    if (output == NULL || (input == NULL && input_len != 0)) {
        return PAYLOADSHIELD_CRYPTO_INVALID;
    }
    output->data = NULL;
    output->len = 0;

    provider = payloadshield_crypto_provider(name);
    if (provider == NULL) {
        return PAYLOADSHIELD_CRYPTO_UNSUPPORTED;
    }
    if (provider->validate_config(config, 1) != PAYLOADSHIELD_CRYPTO_OK) {
        return PAYLOADSHIELD_CRYPTO_INVALID;
    }
    if (provider->init != NULL
        && provider->init(config) != PAYLOADSHIELD_CRYPTO_OK)
    {
        if (provider->cleanup != NULL) provider->cleanup();
        return PAYLOADSHIELD_CRYPTO_FAILURE;
    }

    status = provider->encrypt(config, input, input_len, output);
    if (provider->cleanup != NULL) {
        provider->cleanup();
    }
    return status;
}

int
payloadshield_crypto_decrypt(const char *name,
    const payloadshield_crypto_config_t *config,
    const unsigned char *input, size_t input_len,
    payloadshield_buffer_t *output)
{
    const payloadshield_crypto_provider_t *provider;
    int status;

    if (output == NULL || input == NULL) {
        return PAYLOADSHIELD_CRYPTO_INVALID;
    }
    output->data = NULL;
    output->len = 0;

    provider = payloadshield_crypto_provider(name);
    if (provider == NULL) {
        return PAYLOADSHIELD_CRYPTO_UNSUPPORTED;
    }
    if (provider->validate_config(config, 0) != PAYLOADSHIELD_CRYPTO_OK) {
        return PAYLOADSHIELD_CRYPTO_INVALID;
    }
    if (provider->init != NULL
        && provider->init(config) != PAYLOADSHIELD_CRYPTO_OK)
    {
        if (provider->cleanup != NULL) provider->cleanup();
        return PAYLOADSHIELD_CRYPTO_FAILURE;
    }

    status = provider->decrypt(config, input, input_len, output);
    if (provider->cleanup != NULL) {
        provider->cleanup();
    }
    return status;
}

void
payloadshield_buffer_free(payloadshield_buffer_t *buffer)
{
    if (buffer == NULL) {
        return;
    }
    if (buffer->data != NULL) {
        OPENSSL_cleanse(buffer->data, buffer->len);
        OPENSSL_free(buffer->data);
    }
    buffer->data = NULL;
    buffer->len = 0;
}