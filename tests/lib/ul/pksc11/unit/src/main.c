#include <stdarg.h>
#include <zephyr/ztest.h>
#include <zephyr/fff.h>

#include <psa/crypto.h>
#include <psa/crypto_extra.h>

#include <external/pkcs11/pkcs11.h>

#include "pkcs11_internal.h"

DEFINE_FFF_GLOBALS

FAKE_VALUE_FUNC(psa_status_t, psa_crypto_init)
FAKE_VALUE_FUNC(psa_status_t, psa_close_key, psa_key_handle_t)
FAKE_VALUE_FUNC(psa_status_t, psa_open_key, mbedtls_svc_key_id_t, psa_key_handle_t*)
FAKE_VALUE_FUNC(psa_status_t, psa_generate_key, const psa_key_attributes_t*, psa_key_id_t*)
FAKE_VOID_FUNC(psa_reset_key_attributes, psa_key_attributes_t*)
FAKE_VALUE_FUNC(psa_status_t, psa_purge_key, psa_key_id_t)
FAKE_VALUE_FUNC(psa_status_t, psa_cipher_encrypt_setup, psa_cipher_operation_t*, psa_key_id_t, psa_algorithm_t)
FAKE_VALUE_FUNC(psa_status_t, psa_cipher_encrypt, psa_key_id_t, psa_algorithm_t, const uint8_t*, size_t, uint8_t*, size_t, size_t*)
FAKE_VALUE_FUNC(psa_status_t, psa_cipher_update, psa_cipher_operation_t*, const uint8_t*, size_t, uint8_t*, size_t, size_t*)
FAKE_VALUE_FUNC(psa_status_t, psa_cipher_finish, psa_cipher_operation_t*, uint8_t*, size_t, size_t*)
FAKE_VALUE_FUNC(psa_status_t, psa_cipher_abort, psa_cipher_operation_t*)
FAKE_VALUE_FUNC(psa_status_t, psa_cipher_decrypt_setup, psa_cipher_operation_t*, psa_key_id_t, psa_algorithm_t)
FAKE_VALUE_FUNC(psa_status_t, psa_cipher_decrypt, psa_key_id_t, psa_algorithm_t, const uint8_t*, size_t, uint8_t*, size_t, size_t*)

void z_log_minimal_printk(const char *fmt, ...)
{
    // Do nothing with it for now
    (void)fmt;
}

static void reset_fakes(){
    RESET_FAKE(psa_crypto_init)
    RESET_FAKE(psa_close_key)
    RESET_FAKE(psa_open_key)
    RESET_FAKE(psa_generate_key)
    RESET_FAKE(psa_reset_key_attributes)
    RESET_FAKE(psa_purge_key)
    RESET_FAKE(psa_cipher_encrypt_setup)
    RESET_FAKE(psa_cipher_encrypt)
    RESET_FAKE(psa_cipher_update)
    RESET_FAKE(psa_cipher_finish)
    RESET_FAKE(psa_cipher_abort)
    RESET_FAKE(psa_cipher_decrypt_setup)
    RESET_FAKE(psa_cipher_decrypt)
}

static void reset_sut(){
    reset_crypto_ctx_for_tests();
}

static void setup_before_test_fixture(void *f){
    reset_fakes();
    reset_sut();
}

ZTEST(ul_pkcs11_unit_testsuite, test__initialize__psa_init_works__returns_success)
{
    psa_crypto_init_fake.return_val = PSA_SUCCESS;

    CK_RV ret = C_Initialize(NULL);

    zassert_equal(ret, CKR_OK, "C_Initialize failed");
}

ZTEST(ul_pkcs11_unit_testsuite, test__initialize__psa_init_fails___returns_error)
{
    psa_crypto_init_fake.return_val = PSA_ERROR_COMMUNICATION_FAILURE;

    CK_RV ret = C_Initialize(NULL);

    zassert_equal(ret, CKR_GENERAL_ERROR, "C_Initialize failed");
}

ZTEST(ul_pkcs11_unit_testsuite, test__finalize__works_and_zero){
    pkcs11_crypto_context_t *ctx = get_crypto_ctx_for_tests();

    ctx->key_id = 1;
    ctx->alg = 2;
    ctx->type = 3;

    CK_RV ret = C_Finalize(NULL);

    zassert_equal(ret, CKR_OK, "C_Finalize failed");
    zassert_equal(ctx->key_id, 0, "Key ID not reset");
    zassert_equal(ctx->alg, 0, "Alg not reset");
    zassert_equal(ctx->type, 0, "Type not reset");
}

ZTEST(ul_pkcs11_unit_testsuite, test__generate_key__pMechanism_nullptr__returns_arguments_bad)
{
    CK_RV ret = C_GenerateKey(0, NULL, NULL, 0, NULL);

    zassert_equal(ret, CKR_ARGUMENTS_BAD, "C_GenerateKey did not respond CKR_ARGUMENTS_BAD on NULL mechanism");
}

ZTEST(ul_pkcs11_unit_testsuite, test__generate_key__invalid_mechanism__returns_mechanism_invalid)
{
    CK_MECHANISM mechanism = {
        .mechanism = CKM_AES_XTS_KEY_GEN,
    };

    CK_RV ret = C_GenerateKey(0, &mechanism, NULL, 0, NULL);

    zassert_equal(ret, CKR_MECHANISM_INVALID, "C_GenerateKey did not reject non-AES keygen");
}

ZTEST(ul_pkcs11_unit_testsuite, test__generate_key__open_key_fails__returns_all_functions_works__returns_success){

}

ZTEST_SUITE(ul_pkcs11_unit_testsuite, NULL, NULL, setup_before_test_fixture, NULL, NULL);
