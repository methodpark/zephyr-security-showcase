#pragma once
#include <psa/crypto_types.h>

typedef struct
{
    psa_key_id_t key_id;
    psa_algorithm_t alg;
    psa_key_type_t type;
} pkcs11_crypto_context_t;

#ifdef CONFIG_ZTEST
pkcs11_crypto_context_t* get_crypto_ctx_for_tests();
void reset_crypto_ctx_for_tests();
#endif