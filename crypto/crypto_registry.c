#include "payloadshield_crypto.h"

#include <openssl/crypto.h>

extern const payloadshield_crypto_provider_t payloadshield_aes_gcm_256_provider;
extern const payloadshield_crypto_provider_t payloadshield_chacha20_poly1305_provider;
extern const payloadshield_crypto_provider_t payloadshield_rsa_hybrid_provider;

static CRYPTO_ONCE payloadshield_registry_once = CRYPTO_ONCE_STATIC_INIT;
static int payloadshield_registry_status = PAYLOADSHIELD_CRYPTO_FAILURE;

static void
payloadshield_crypto_register_builtins_once(void)
{
    if (payloadshield_crypto_register(&payloadshield_aes_gcm_256_provider)
            != PAYLOADSHIELD_CRYPTO_OK
        || payloadshield_crypto_register(&payloadshield_chacha20_poly1305_provider)
            != PAYLOADSHIELD_CRYPTO_OK
        || payloadshield_crypto_register(&payloadshield_rsa_hybrid_provider)
            != PAYLOADSHIELD_CRYPTO_OK)
    {
        return;
    }
    payloadshield_registry_status = PAYLOADSHIELD_CRYPTO_OK;
}

int
payloadshield_crypto_register_builtins(void)
{
    if (CRYPTO_THREAD_run_once(&payloadshield_registry_once,
                               payloadshield_crypto_register_builtins_once) != 1)
    {
        return PAYLOADSHIELD_CRYPTO_FAILURE;
    }
    return payloadshield_registry_status;
}