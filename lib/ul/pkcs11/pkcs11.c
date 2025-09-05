/*
 * SPDX-FileCopyrightText: 2025 UL Solutions - Software Intensive Systems
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdio.h>
#include <zephyr/kernel.h>
#include <zephyr/logging/log.h>

#include <psa/crypto.h>
#include <psa/crypto_extra.h>

#include <external/pkcs11/pkcs11.h>

LOG_MODULE_REGISTER(ul_pkcs11, LOG_LEVEL_INF);

#include "pkcs11_args_helper.h"
#include "pkcs11_internal.h"

static pkcs11_crypto_context_t g_ctx;

static psa_cipher_operation_t g_encryptOp = PSA_CIPHER_OPERATION_INIT;
static psa_cipher_operation_t g_decryptOp = PSA_CIPHER_OPERATION_INIT;

CK_RV C_Initialize(CK_VOID_PTR pInitArgs)
{
    (void)pInitArgs;
    psa_status_t status;

    /* Initialize PSA Crypto */
    status = psa_crypto_init();
    if (status != PSA_SUCCESS)
    {
        LOG_ERR("psa_crypto_init failed! (Error: %d)", status);
        return CKR_GENERAL_ERROR;
    }

    return CKR_OK;
}

CK_RV C_Finalize(CK_VOID_PTR pInitArgs)
{
    (void)pInitArgs;
    memset(&g_ctx, 0, sizeof(g_ctx));
    LOG_INF("successfully finalized");
    return CKR_OK;
}

CK_RV C_GenerateKey(CK_SESSION_HANDLE hSession,
                    CK_MECHANISM_PTR pMechanism,
                    CK_ATTRIBUTE_PTR pTemplate,
                    CK_ULONG ulCount,
                    CK_OBJECT_HANDLE_PTR pObjHdl)
{
    (void)hSession;
    (void)pTemplate;
    (void)ulCount;
    (void)pObjHdl;

    CKR_CHECK_NULL(pMechanism);

    // Only AES key generation supported in this mock
    if (pMechanism->mechanism != CKM_AES_KEY_GEN)
    {
        LOG_ERR("Unsupported mechanism: %lu", pMechanism->mechanism);
        return CKR_MECHANISM_INVALID;
    }

    g_ctx = (pkcs11_crypto_context_t){
        .key_id = PSA_KEY_ID_USER_MIN,
        .alg = PSA_ALG_CTR,
        .type = PSA_KEY_TYPE_AES
    };

    psa_key_handle_t handle;
    psa_status_t status = psa_open_key(g_ctx.key_id, &handle);

    if (status == PSA_SUCCESS)
    {
        psa_close_key(handle);
        LOG_INF("Key already exists, stored in session context: %lu", (unsigned long)g_ctx.key_id);
        return CKR_OK;
    }
    else if (status != PSA_ERROR_DOES_NOT_EXIST)
    {
        LOG_ERR("psa_open_key failed! (Error: %d)", status);
        return CKR_FUNCTION_FAILED;
    }

    // Configure key attributes
    psa_key_attributes_t key_attributes = PSA_KEY_ATTRIBUTES_INIT;
    psa_set_key_usage_flags(&key_attributes, PSA_KEY_USAGE_ENCRYPT | PSA_KEY_USAGE_DECRYPT);
    psa_set_key_algorithm(&key_attributes, g_ctx.alg);
    psa_set_key_type(&key_attributes, g_ctx.type);
    psa_set_key_bits(&key_attributes, 128);

    // Persistent key specific settings
    psa_set_key_lifetime(&key_attributes, PSA_KEY_LIFETIME_PERSISTENT);
    psa_set_key_id(&key_attributes, PSA_KEY_ID_USER_MIN);

    // Generate key
    status = psa_generate_key(&key_attributes, &g_ctx.key_id);
    if (status != PSA_SUCCESS)
    {
        LOG_ERR("psa_generate_key failed! (Error: %d)", status);
        psa_reset_key_attributes(&key_attributes);
        return CKR_FUNCTION_FAILED;
    }

    // Purge from volatile memory
    status = psa_purge_key(g_ctx.key_id);
    if (status != PSA_SUCCESS)
    {
        LOG_ERR("psa_purge_key failed! (Error: %d)", status);
        psa_reset_key_attributes(&key_attributes);
        return CKR_FUNCTION_FAILED;
    }

    psa_reset_key_attributes(&key_attributes);

    LOG_INF("Persistent key generated successfully! ID: %lu", (unsigned long)g_ctx.key_id);

    return CKR_OK;
}

CK_RV C_EncryptInit(CK_SESSION_HANDLE hSession,
                    CK_MECHANISM_PTR pMechanism,
                    CK_OBJECT_HANDLE hKey)
{
    (void)hSession;
    (void)pMechanism;
    (void)hKey;

    psa_key_handle_t status = psa_cipher_encrypt_setup(&g_encryptOp, g_ctx.key_id, g_ctx.alg);
    if (status != PSA_SUCCESS)
    {
        LOG_ERR("psa_cipher_encrypt_setup failed! (Error: %d)", status);
        return CKR_FUNCTION_FAILED;
    }

    return CKR_OK;
}

CK_RV C_Encrypt(CK_SESSION_HANDLE hSession,
                CK_BYTE_PTR pData,
                CK_ULONG ulDataLen,
                CK_BYTE_PTR pEncryptedData,
                CK_ULONG_PTR pulEncryptedDataLen)
{
    (void)hSession;

    CKR_CHECK_NULL(pData);
    CKR_CHECK_NULL(pEncryptedData);
    CKR_CHECK_NULL(pulEncryptedDataLen);
    CKR_CHECK_ZERO(ulDataLen);

    psa_status_t status = psa_cipher_encrypt(g_ctx.key_id, g_ctx.alg,
                                pData, ulDataLen,
                                pEncryptedData, *pulEncryptedDataLen,
                                (size_t *)pulEncryptedDataLen);
    if (status != PSA_SUCCESS)
    {
        LOG_ERR("psa_cipher_encrypt failed! (Error: %d)", status);
        return CKR_FUNCTION_FAILED;
    }

    return PSA_SUCCESS;
}

CK_RV C_DecryptInit(CK_SESSION_HANDLE hSession,
                    CK_MECHANISM_PTR pMechanism,
                    CK_OBJECT_HANDLE hKey)
{
    (void)hSession;
    (void)pMechanism;
    (void)hKey;

    psa_status_t status = psa_cipher_decrypt_setup(&g_decryptOp, g_ctx.key_id, g_ctx.alg);
    if (status != PSA_SUCCESS)
    {
        LOG_ERR("psa_cipher_decrypt_setup failed! (Error: %d)", status);
        return CKR_FUNCTION_FAILED;
    }

    return CKR_OK;
}

CK_RV C_Decrypt(CK_SESSION_HANDLE hSession,
                CK_BYTE_PTR pEncryptedData,
                CK_ULONG ulEncryptedDataLen,
                CK_BYTE_PTR pData,
                CK_ULONG_PTR pulDataLen)
{
    (void)hSession;

    CKR_CHECK_NULL(pEncryptedData);
    CKR_CHECK_NULL(pData);
    CKR_CHECK_NULL(pulDataLen);
    CKR_CHECK_ZERO(ulEncryptedDataLen);

    psa_status_t status = psa_cipher_decrypt(g_ctx.key_id, g_ctx.alg, pEncryptedData,
                                ulEncryptedDataLen, pData,
                                *pulDataLen, (size_t *)pulDataLen);
    if (status != PSA_SUCCESS)
    {
        LOG_ERR("psa_cipher_decrypt failed! (Error: %d)", status);
        return CKR_FUNCTION_FAILED;
    }

    return CKR_OK;
}

#ifdef CONFIG_ZTEST

pkcs11_crypto_context_t* get_crypto_ctx_for_tests() {
    return &g_ctx;
}

void reset_crypto_ctx_for_tests() {
    memset(&g_ctx, 0, sizeof(g_ctx));
}

#endif
