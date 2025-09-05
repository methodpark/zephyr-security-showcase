/*
 * SPDX-FileCopyrightText: 2025 UL Solutions - Software Intensive Systems
 *
 * SPDX-License-Identifier: Apache-2.0
 */


#include <zephyr/ztest.h>
#include <zephyr/storage/flash_map.h>

#include <psa/crypto.h>

#include <external/pkcs11/pkcs11.h>


static CK_SESSION_HANDLE hSession = 0x0;
static CK_OBJECT_HANDLE hKey = PSA_KEY_ID_USER_MIN;

static void ztest_setup(void *f)
{
    CK_MECHANISM mechanism = {CKM_AES_KEY_GEN, NULL, 0};

    CK_RV ret = C_Initialize(NULL);
    zassert_equal(ret, CKR_OK, "C_Initialize failed!");

    ret = C_GenerateKey(hSession, &mechanism, NULL, 0, &hKey);
    zassert_equal(ret, CKR_OK, "C_GenerateKey failed!");
}

static void ztest_teardown(void *f)
{
    // This is not great as it leaks that we use psa underneath,
    // but as we don't use the handleObject parameter (see GH issue #5),
    // we can't use C_DestroyObject to clean up.
    // So we just destroy the (known) key directly for sake of simplicity.
    psa_status_t psa_ret = psa_destroy_key(PSA_KEY_ID_USER_MIN);
    zassert_equal(psa_ret, PSA_SUCCESS, "psa_destroy_key failed!");

    CK_RV ret = C_Finalize(NULL);
    zassert_equal(ret, CKR_OK, "C_Finalize failed!");
}

ZTEST(ul_pkcs11_integration_testsuite, test__setup_teardown_only_no_encrypt__successful)
{
    // don't do any encryption, just setup and teardown
}

ZTEST(ul_pkcs11_integration_testsuite, test__encrypt_simple_string__different_from_original)
{
    CK_BYTE plaintext[] = "Hello World!";
    CK_ULONG plaintext_len = sizeof(plaintext);

    CK_BYTE ciphertext[sizeof(plaintext) * 4]; // Ensure enough space for encryption
    CK_ULONG ciphertext_len = sizeof(ciphertext);

    CK_RV ret = C_Encrypt(hSession, plaintext, plaintext_len, ciphertext, &ciphertext_len);
    zassert_equal(ret, CKR_OK, "C_Encrypt failed!");
    zassert_not_equal(memcmp(plaintext, ciphertext, plaintext_len), 0, "Ciphertext matches plaintext!");
}

ZTEST(ul_pkcs11_integration_testsuite, test__encrypt_and_decrypt_simple_string__matches_original)
{
    CK_RV ret;

    CK_BYTE plaintext[] = "Hello World!";
    CK_ULONG plaintext_len = sizeof(plaintext);

    CK_BYTE ciphertext[sizeof(plaintext) * 4]; // Ensure enough space for encryption
    CK_ULONG ciphertext_len = sizeof(ciphertext);

    ret = C_Encrypt(hSession, plaintext, plaintext_len, ciphertext, &ciphertext_len);
    zassert_equal(ret, CKR_OK, "C_Encrypt failed!");

    CK_BYTE decryptedtext[sizeof(plaintext)];
    CK_ULONG decryptedtext_len = sizeof(decryptedtext);

    ret = C_Decrypt(hSession, ciphertext, ciphertext_len, decryptedtext, &decryptedtext_len);
    zassert_equal(ret, CKR_OK, "C_Decrypt failed!");
    zassert_equal(decryptedtext_len, plaintext_len, "Decrypted text length mismatch!");
    zassert_mem_equal(decryptedtext, plaintext, plaintext_len, "Decrypted text does not match original!");
}

ZTEST(ul_pkcs11_integration_testsuite, test__encrypt_too_small_buffersize__correctly_fails)
{
    CK_RV ret;

    CK_BYTE plaintext[] = "This is a test string, and the encryption buffer is too small for that!";
    CK_ULONG plaintext_len = sizeof(plaintext);

    CK_BYTE ciphertext[16]; // Intentionally too small
    CK_ULONG ciphertext_len = sizeof(ciphertext);

    ret = C_Encrypt(hSession, plaintext, plaintext_len, ciphertext, &ciphertext_len);
    zassert_equal(ret, CKR_FUNCTION_FAILED, "C_Encrypt should have failed!");
}


ZTEST(ul_pkcs11_integration_testsuite, test__decrypt_too_small_buffersize__correctly_fails)
{
    CK_RV ret;

    CK_BYTE plaintext[] = "Hello World!";
    CK_ULONG plaintext_len = sizeof(plaintext);

    CK_BYTE ciphertext[sizeof(plaintext) * 4]; // Ensure enough space for encryption
    CK_ULONG ciphertext_len = sizeof(ciphertext);

    ret = C_Encrypt(hSession, plaintext, plaintext_len, ciphertext, &ciphertext_len);
    zassert_equal(ret, CKR_OK, "C_Encrypt failed!");

    CK_BYTE decryptedtext[8]; // Intentionally too small
    CK_ULONG decryptedtext_len = sizeof(decryptedtext);

    ret = C_Decrypt(hSession, ciphertext, ciphertext_len, decryptedtext, &decryptedtext_len);
    zassert_equal(ret, CKR_FUNCTION_FAILED, "C_Decrypt should have failed!");
}

ZTEST_SUITE(ul_pkcs11_integration_testsuite, NULL, NULL, ztest_setup, ztest_teardown, NULL);
