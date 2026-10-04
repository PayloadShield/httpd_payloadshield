#include "aead_provider.h"

static int
payloadshield_aes_gcm_encrypt(const payloadshield_crypto_config_t *config,
    const unsigned char *input, size_t input_len,
    payloadshield_buffer_t *output)
{
    return payloadshield_aead_encrypt(EVP_aes_256_gcm(), config, input,
                                      input_len, output);
}

static int
payloadshield_aes_gcm_decrypt(const payloadshield_crypto_config_t *config,
    const unsigned char *input, size_t input_len,
    payloadshield_buffer_t *output)
{
    return payloadshield_aead_decrypt(EVP_aes_256_gcm(), config, input,
                                      input_len, output);
}

const payloadshield_crypto_provider_t payloadshield_aes_gcm_256_provider = {
    "aes-gcm-256",
    NULL,
    NULL,
    payloadshield_aead_validate,
    payloadshield_aes_gcm_encrypt,
    payloadshield_aes_gcm_decrypt
};