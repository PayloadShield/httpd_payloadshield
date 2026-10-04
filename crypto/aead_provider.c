#include "aead_provider.h"

#include <limits.h>
#include <stdint.h>
#include <string.h>

#include <openssl/crypto.h>
#include <openssl/rand.h>

#define PAYLOADSHIELD_NONCE_SIZE 12
#define PAYLOADSHIELD_TAG_SIZE 16
#define PAYLOADSHIELD_AEAD_OVERHEAD (PAYLOADSHIELD_NONCE_SIZE + PAYLOADSHIELD_TAG_SIZE)

int
payloadshield_aead_validate(const payloadshield_crypto_config_t *config,
    int encrypting)
{
    (void) encrypting;
    if (config == NULL || config->key == NULL || config->key_len != 32) {
        return PAYLOADSHIELD_CRYPTO_INVALID;
    }
    return PAYLOADSHIELD_CRYPTO_OK;
}

int
payloadshield_aead_encrypt(const EVP_CIPHER *cipher,
    const payloadshield_crypto_config_t *config,
    const unsigned char *input, size_t input_len,
    payloadshield_buffer_t *output)
{
    EVP_CIPHER_CTX *ctx = NULL;
    unsigned char nonce[PAYLOADSHIELD_NONCE_SIZE];
    unsigned char *result = NULL;
    int written = 0;
    int final_written = 0;
    size_t allocation;
    int status = PAYLOADSHIELD_CRYPTO_FAILURE;

    if (payloadshield_aead_validate(config, 1) != PAYLOADSHIELD_CRYPTO_OK
        || (input == NULL && input_len != 0)
        || input_len > INT_MAX
        || (config->max_payload_size != 0 && input_len > config->max_payload_size)
        || input_len > SIZE_MAX - PAYLOADSHIELD_AEAD_OVERHEAD)
    {
        return PAYLOADSHIELD_CRYPTO_INVALID;
    }

    allocation = input_len + PAYLOADSHIELD_AEAD_OVERHEAD;
    result = OPENSSL_malloc(allocation == 0 ? 1 : allocation);
    ctx = EVP_CIPHER_CTX_new();
    if (result == NULL || ctx == NULL) {
        status = PAYLOADSHIELD_CRYPTO_NOMEM;
        goto done;
    }

    if (RAND_bytes(nonce, sizeof(nonce)) != 1
        || EVP_EncryptInit_ex(ctx, cipher, NULL, NULL, NULL) != 1
        || EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN,
                              sizeof(nonce), NULL) != 1
        || EVP_EncryptInit_ex(ctx, NULL, NULL, config->key, nonce) != 1)
    {
        goto done;
    }

    memcpy(result, nonce, sizeof(nonce));
    if (input_len != 0
        && EVP_EncryptUpdate(ctx, result + sizeof(nonce), &written,
                             input, (int) input_len) != 1)
    {
        goto done;
    }
    if (EVP_EncryptFinal_ex(ctx, result + sizeof(nonce) + written,
                            &final_written) != 1
        || EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG,
                              PAYLOADSHIELD_TAG_SIZE,
                              result + sizeof(nonce) + written + final_written) != 1)
    {
        goto done;
    }

    output->data = result;
    output->len = sizeof(nonce) + (size_t) written + (size_t) final_written
                  + PAYLOADSHIELD_TAG_SIZE;
    result = NULL;
    status = PAYLOADSHIELD_CRYPTO_OK;

done:
    EVP_CIPHER_CTX_free(ctx);
    if (result != NULL) {
        OPENSSL_clear_free(result, allocation == 0 ? 1 : allocation);
    }
    OPENSSL_cleanse(nonce, sizeof(nonce));
    return status;
}

int
payloadshield_aead_decrypt(const EVP_CIPHER *cipher,
    const payloadshield_crypto_config_t *config,
    const unsigned char *input, size_t input_len,
    payloadshield_buffer_t *output)
{
    EVP_CIPHER_CTX *ctx = NULL;
    unsigned char *plaintext = NULL;
    size_t ciphertext_len;
    int written = 0;
    int final_written = 0;
    int status = PAYLOADSHIELD_CRYPTO_FAILURE;

    if (payloadshield_aead_validate(config, 0) != PAYLOADSHIELD_CRYPTO_OK
        || input == NULL || input_len < PAYLOADSHIELD_AEAD_OVERHEAD)
    {
        return PAYLOADSHIELD_CRYPTO_INVALID;
    }

    ciphertext_len = input_len - PAYLOADSHIELD_AEAD_OVERHEAD;
    if (ciphertext_len > INT_MAX
        || (config->max_payload_size != 0
            && ciphertext_len > config->max_payload_size))
    {
        return PAYLOADSHIELD_CRYPTO_INVALID;
    }

    plaintext = OPENSSL_malloc(ciphertext_len == 0 ? 1 : ciphertext_len);
    ctx = EVP_CIPHER_CTX_new();
    if (plaintext == NULL || ctx == NULL) {
        status = PAYLOADSHIELD_CRYPTO_NOMEM;
        goto done;
    }

    if (EVP_DecryptInit_ex(ctx, cipher, NULL, NULL, NULL) != 1
        || EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN,
                              PAYLOADSHIELD_NONCE_SIZE, NULL) != 1
        || EVP_DecryptInit_ex(ctx, NULL, NULL, config->key, input) != 1)
    {
        goto done;
    }

    if (ciphertext_len != 0
        && EVP_DecryptUpdate(ctx, plaintext, &written,
                             input + PAYLOADSHIELD_NONCE_SIZE,
                             (int) ciphertext_len) != 1)
    {
        goto done;
    }
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG,
                            PAYLOADSHIELD_TAG_SIZE,
                            (void *) (input + input_len - PAYLOADSHIELD_TAG_SIZE)) != 1)
    {
        goto done;
    }
    if (EVP_DecryptFinal_ex(ctx, plaintext + written, &final_written) != 1) {
        status = PAYLOADSHIELD_CRYPTO_AUTH;
        goto done;
    }

    output->data = plaintext;
    output->len = (size_t) written + (size_t) final_written;
    plaintext = NULL;
    status = PAYLOADSHIELD_CRYPTO_OK;

done:
    EVP_CIPHER_CTX_free(ctx);
    if (plaintext != NULL) {
        OPENSSL_clear_free(plaintext, ciphertext_len == 0 ? 1 : ciphertext_len);
    }
    return status;
}