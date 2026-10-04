#ifndef PAYLOADSHIELD_AEAD_PROVIDER_H
#define PAYLOADSHIELD_AEAD_PROVIDER_H

#include "payloadshield_crypto.h"

int payloadshield_aead_validate(const payloadshield_crypto_config_t *config,
    int encrypting);
int payloadshield_aead_encrypt(const EVP_CIPHER *cipher,
    const payloadshield_crypto_config_t *config,
    const unsigned char *input, size_t input_len,
    payloadshield_buffer_t *output);
int payloadshield_aead_decrypt(const EVP_CIPHER *cipher,
    const payloadshield_crypto_config_t *config,
    const unsigned char *input, size_t input_len,
    payloadshield_buffer_t *output);

#endif