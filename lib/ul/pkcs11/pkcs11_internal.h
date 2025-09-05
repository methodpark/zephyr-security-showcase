/*
 * SPDX-FileCopyrightText: 2025 UL Solutions - Software Intensive Systems
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#pragma once
#include <psa/crypto_types.h>

typedef struct
{
    psa_key_id_t key_id;
    psa_algorithm_t alg;
    psa_key_type_t type;
    bool encrypt_mode_active;
    bool decrypt_mode_active;
} pkcs11_crypto_context_t;

#ifdef CONFIG_ZTEST
pkcs11_crypto_context_t* get_crypto_ctx_for_tests();
void reset_crypto_ctx_for_tests();
#endif
