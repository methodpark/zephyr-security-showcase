#include <assert.h>
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


// To capture the attributes passed to psa_generate_key
static psa_key_attributes_t copied_attrs;

static psa_status_t psa_gen_key_capture_attrs(const psa_key_attributes_t* attributes, psa_key_id_t* key) {

    assert(attributes != NULL);
    assert(key != NULL);

    copied_attrs = *attributes;
    *key = 0x857883;

    return PSA_SUCCESS;
}


ZTEST(ul_pkcs11_unit_testsuite, test__generate_key__new_key_psa_functions_succeed__returns_success){
    psa_open_key_fake.return_val = PSA_ERROR_DOES_NOT_EXIST;
    psa_generate_key_fake.custom_fake = psa_gen_key_capture_attrs;
    psa_purge_key_fake.return_val = PSA_SUCCESS;

    CK_MECHANISM mechanism = {
        .mechanism = CKM_AES_KEY_GEN,
    };

    CK_RV ret = C_GenerateKey(0, &mechanism, NULL, 0, NULL);

    zassert_equal(ret, CKR_OK, "C_GenerateKey failed");

    zassert_equal(psa_open_key_fake.call_count, 1, "psa_open_key not called");
    zassert_equal(psa_generate_key_fake.call_count, 1, "psa_generate_key not called");
    zassert_equal(psa_purge_key_fake.call_count, 1, "psa_purge_key not called");

    zassert_equal(psa_get_key_type(&copied_attrs), PSA_KEY_TYPE_AES, "Key type incorrect");
    zassert_equal(psa_get_key_bits(&copied_attrs), 128, "Key bits incorrect");
    zassert_equal(psa_get_key_usage_flags(&copied_attrs), PSA_KEY_USAGE_ENCRYPT | PSA_KEY_USAGE_DECRYPT, "Key usage incorrect");
    zassert_equal(psa_get_key_algorithm(&copied_attrs), PSA_ALG_CTR, "Key algorithm incorrect");
    zassert_equal(psa_get_key_lifetime(&copied_attrs), PSA_KEY_LIFETIME_PERSISTENT, "Key lifetime incorrect");
    zassert_equal(psa_get_key_id(&copied_attrs), PSA_KEY_ID_USER_MIN, "Key ID incorrect");
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

ZTEST(ul_pkcs11_unit_testsuite, test__generate_key__key_already_exists__returns_success){

    psa_open_key_fake.return_val = PSA_SUCCESS;
    psa_close_key_fake.return_val = PSA_SUCCESS;

    CK_MECHANISM mechanism = {
        .mechanism = CKM_AES_KEY_GEN,
    };

    CK_RV ret = C_GenerateKey(0, &mechanism, NULL, 0, NULL);

    zassert_equal(ret, CKR_OK, "C_GenerateKey failed");

    zassert_equal(psa_open_key_fake.call_count, 1, "psa_open_key not called");
    zassert_equal(psa_close_key_fake.call_count, 1, "psa_close_key not called");
    zassert_equal(psa_generate_key_fake.call_count, 0, "psa_generate_key called unexpectedly");
}

ZTEST(ul_pkcs11_unit_testsuite, test__generate_key__psa_open_key_fails_unexpectedly__returns_function_failed){
    psa_open_key_fake.return_val = PSA_ERROR_COMMUNICATION_FAILURE;

    CK_MECHANISM mechanism = {
        .mechanism = CKM_AES_KEY_GEN,
    };

    CK_RV ret = C_GenerateKey(0, &mechanism, NULL, 0, NULL);

    zassert_equal(ret, CKR_FUNCTION_FAILED, "C_GenerateKey did not fail");

    zassert_equal(psa_open_key_fake.call_count, 1, "psa_open_key not called");
    zassert_equal(psa_generate_key_fake.call_count, 0, "psa_generate_key called unexpectedly");
}

ZTEST(ul_pkcs11_unit_testsuite, test__generate_key__psa_generate_key_fails__returns_function_failed){
    psa_open_key_fake.return_val = PSA_ERROR_DOES_NOT_EXIST;
    psa_generate_key_fake.return_val = PSA_ERROR_COMMUNICATION_FAILURE;

    CK_MECHANISM mechanism = {
        .mechanism = CKM_AES_KEY_GEN,
    };

    CK_RV ret = C_GenerateKey(0, &mechanism, NULL, 0, NULL);

    zassert_equal(ret, CKR_FUNCTION_FAILED, "C_GenerateKey did not fail");

    zassert_equal(psa_reset_key_attributes_fake.call_count, 1, "psa_reset_key_attributes not called");
    zassert_equal(psa_purge_key_fake.call_count, 0, "psa_purge_key called unexpectedly");
}

ZTEST(ul_pkcs11_unit_testsuite, test__generate_key__psa_purge_key_fails__returns_function_failed){
    psa_open_key_fake.return_val = PSA_ERROR_DOES_NOT_EXIST;
    psa_generate_key_fake.return_val = PSA_SUCCESS;
    psa_purge_key_fake.return_val = PSA_ERROR_COMMUNICATION_FAILURE;

    CK_MECHANISM mechanism = {
        .mechanism = CKM_AES_KEY_GEN,
    };

    CK_RV ret = C_GenerateKey(0, &mechanism, NULL, 0, NULL);

    zassert_equal(ret, CKR_FUNCTION_FAILED, "C_GenerateKey did not fail");

    zassert_equal(psa_reset_key_attributes_fake.call_count, 1, "psa_reset_key_attributes not called");
    zassert_equal(psa_purge_key_fake.call_count, 1, "psa_purge_key not called");
}

ZTEST_SUITE(ul_pkcs11_unit_testsuite, NULL, NULL, setup_before_test_fixture, NULL, NULL);
