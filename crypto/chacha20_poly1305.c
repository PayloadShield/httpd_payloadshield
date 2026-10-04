#include "aead_provider.h"

static int
payloadshield_chacha_encrypt(const payloadshield_crypto_config_t *config,
    const unsigned char *input, size_t input_len,
    payloadshield_buffer_t *output)
{
    const EVP_CIPHER *cipher = EVP_chacha20_poly1305();
    if (cipher == NULL) {
        return PAYLOADSHIELD_CRYPTO_UNSUPPORTED;
    }
    return payloadshield_aead_encrypt(cipher, config, input, input_len, output);
}

static int
payloadshield_chacha_decrypt(const payloadshield_crypto_config_t *config,
    const unsigned char *input, size_t input_len,
    payloadshield_buffer_t *output)
{
    const EVP_CIPHER *cipher = EVP_chacha20_poly1305();
    if (cipher == NULL) {
        return PAYLOADSHIELD_CRYPTO_UNSUPPORTED;
    }
    return payloadshield_aead_decrypt(cipher, config, input, input_len, output);
}

const payloadshield_crypto_provider_t payloadshield_chacha20_poly1305_provider = {
    "chacha20-poly1305",
    NULL,
    NULL,
    payloadshield_aead_validate,
    payloadshield_chacha_encrypt,
    payloadshield_chacha_decrypt
};