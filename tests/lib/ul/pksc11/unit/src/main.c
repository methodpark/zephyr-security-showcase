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
FAKE_VALUE_FUNC(psa_status_t, psa_cipher_finish, psa_cipher_operation_t*, uint8_t*, size_t, size_t*)
FAKE_VALUE_FUNC(psa_status_t, psa_cipher_abort, psa_cipher_operation_t*)
FAKE_VALUE_FUNC(psa_status_t, psa_cipher_decrypt_setup, psa_cipher_operation_t*, psa_key_id_t, psa_algorithm_t)
FAKE_VALUE_FUNC(psa_status_t, psa_cipher_decrypt, psa_key_id_t, psa_algorithm_t, const uint8_t*, size_t, uint8_t*, size_t, size_t*)

#define DATA_LEN 16
#define ENCRYPTED_BUFFER_LEN 32

void z_log_minimal_printk(const char *fmt, ...)
{
    // Do nothing with it for now
    (void)fmt;
}

static psa_key_id_t GLOBAL_KEY_ID = 0x857883;

static void reset_fakes(){
    RESET_FAKE(psa_crypto_init)
    RESET_FAKE(psa_close_key)
    RESET_FAKE(psa_open_key)
    RESET_FAKE(psa_generate_key)
    RESET_FAKE(psa_reset_key_attributes)
    RESET_FAKE(psa_purge_key)
    RESET_FAKE(psa_cipher_encrypt_setup)
    RESET_FAKE(psa_cipher_encrypt)
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

static void manually_initialize_global_crypto_context() {
    pkcs11_crypto_context_t *ctx = get_crypto_ctx_for_tests();
    ctx->key_id = GLOBAL_KEY_ID;
    ctx->alg = PSA_ALG_CTR;
    ctx->type = PSA_KEY_TYPE_AES;
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

static psa_status_t psa_cipher_encrypt_fake_impl(mbedtls_svc_key_id_t key,
                                                psa_algorithm_t alg,
                                                const uint8_t *input,
                                                size_t input_length,
                                                uint8_t *output,
                                                size_t output_size,
                                                size_t *output_length)
{

    assert(input != NULL);
    assert(output != NULL);
    assert(output_length != NULL);

    assert(output_size >= 3);

    *output_length = 3;
    output[0] = 0xAB;
    output[1] = 0xCD;
    output[2] = 0xEF;
    return PSA_SUCCESS;
}

static psa_status_t psa_cipher_decrypt_fake_impl(mbedtls_svc_key_id_t key,
                                                psa_algorithm_t alg,
                                                const uint8_t *input,
                                                size_t input_length,
                                                uint8_t *output,
                                                size_t output_size,
                                                size_t *output_length)
{

    assert(input != NULL);
    assert(output != NULL);
    assert(output_length != NULL);

    assert(output_size >= 11);

    for(int i = 0; i < 11; i++) {
        output[i] = i;
    }
    *output_length = 11;
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

ZTEST(ul_pkcs11_unit_testsuite, test__encrypt_init__psa_cipher_encrypt_setup_fails__returns_function_failed){
    psa_cipher_encrypt_setup_fake.return_val = PSA_ERROR_COMMUNICATION_FAILURE;

    CK_RV ret = C_EncryptInit(0, NULL, 0);

    zassert_equal(ret, CKR_FUNCTION_FAILED, "C_EncryptInit did not fail");
    zassert_equal(psa_cipher_encrypt_setup_fake.call_count, 1, "psa_cipher_encrypt_setup not called");
}

ZTEST(ul_pkcs11_unit_testsuite, test__encrypt_init__psa_functions_succeed__returns_success){
    psa_cipher_encrypt_setup_fake.return_val = PSA_SUCCESS;

    manually_initialize_global_crypto_context();

    CK_RV ret = C_EncryptInit(0, NULL, 0);

    zassert_equal(ret, CKR_OK, "C_EncryptInit failed");

    zassert_equal(psa_cipher_encrypt_setup_fake.call_count, 1, "psa_cipher_encrypt_setup not called");

    zassert_equal(psa_cipher_encrypt_setup_fake.arg1_val, GLOBAL_KEY_ID, "psa_cipher_encrypt_setup called with wrong key ID");
    zassert_equal(psa_cipher_encrypt_setup_fake.arg2_val, PSA_ALG_CTR, "psa_cipher_encrypt_setup called with wrong algorithm");
}

ZTEST(ul_pkcs11_unit_testsuite, test__encrypt__psa_cipher_encrypt_fails__returns_function_failed){
    psa_cipher_encrypt_fake.return_val = PSA_ERROR_COMMUNICATION_FAILURE;

    manually_initialize_global_crypto_context();

    uint8_t data[DATA_LEN] = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10};
    uint8_t encrypted[ENCRYPTED_BUFFER_LEN] = {0};

    long unsigned int encrypted_buffer_len = sizeof(encrypted);

    uint8_t data_safe[DATA_LEN];
    memcpy(data_safe, data, sizeof(data));

    CK_RV ret = C_Encrypt(0, data, sizeof(data), encrypted, &encrypted_buffer_len);

    zassert_equal(ret, CKR_FUNCTION_FAILED, "C_Encrypt did not fail");
    zassert_equal(psa_cipher_encrypt_fake.call_count, 1, "psa_cipher_encrypt not called");

    zassert_mem_equal(encrypted, (uint8_t[ENCRYPTED_BUFFER_LEN]){0}, ENCRYPTED_BUFFER_LEN, "Encrypted data unexpectedly written on fail");

    zassert_mem_equal(data, data_safe, sizeof(data), "Input data was modified unexpectedly");
    zassert_equal(encrypted_buffer_len, ENCRYPTED_BUFFER_LEN, "Encrypted buffer length was modified unexpectedly");
}

ZTEST(ul_pkcs11_unit_testsuite, test__encrypt__psa_cipher_encrypt_succeeds__returns_success){
    psa_cipher_encrypt_fake.custom_fake = psa_cipher_encrypt_fake_impl;

    manually_initialize_global_crypto_context();

    uint8_t data[DATA_LEN] = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10};
    uint8_t encrypted[ENCRYPTED_BUFFER_LEN] = {0};
    uint8_t expected_encrypted[ENCRYPTED_BUFFER_LEN] = {0xAB, 0xCD, 0xEF};

    long unsigned int encrypted_buffer_len = sizeof(encrypted);

    uint8_t data_safe[DATA_LEN];
    memcpy(data_safe, data, sizeof(data));

    CK_RV ret = C_Encrypt(0, data, sizeof(data), encrypted, &encrypted_buffer_len);

    zassert_equal(ret, CKR_OK, "C_Encrypt did fail");

    zassert_mem_equal(encrypted, expected_encrypted, ENCRYPTED_BUFFER_LEN, "Encrypted data was not correctly written");
    zassert_equal(encrypted_buffer_len, 3, "Encrypted buffer length was not set correctly");

    zassert_mem_equal(data, data_safe, sizeof(data), "Input data was modified unexpectedly");

    zassert_equal(psa_cipher_encrypt_fake.call_count, 1, "psa_cipher_encrypt not called");
    zassert_equal(psa_cipher_encrypt_fake.arg0_val, GLOBAL_KEY_ID, "psa_cipher_encrypt called with wrong key ID");
    zassert_equal(psa_cipher_encrypt_fake.arg1_val, PSA_ALG_CTR, "psa_cipher_encrypt called with wrong algorithm");
    zassert_equal_ptr(psa_cipher_encrypt_fake.arg2_val, (uintptr_t)data, "psa_cipher_encrypt called with wrong data pointer");
    zassert_equal(psa_cipher_encrypt_fake.arg3_val, sizeof(data), "psa_cipher_encrypt called with wrong data length");
    zassert_equal_ptr(psa_cipher_encrypt_fake.arg4_val, (uintptr_t)encrypted, "psa_cipher_encrypt called with wrong encrypted data pointer");
    zassert_equal(psa_cipher_encrypt_fake.arg5_val, ENCRYPTED_BUFFER_LEN, "psa_cipher_encrypt called with wrong encrypted data buffer length");
    zassert_equal_ptr(psa_cipher_encrypt_fake.arg6_val, (uintptr_t)&encrypted_buffer_len, "psa_cipher_encrypt called with wrong encrypted data length pointer");
}

ZTEST(ul_pkcs11_unit_testsuite, test__encrypt__pData_nullptr__returns_arguments_bad){
    long unsigned int encrypted_buffer_len = ENCRYPTED_BUFFER_LEN;
    uint8_t encrypted[ENCRYPTED_BUFFER_LEN] = {0};

    CK_RV ret = C_Encrypt(0, NULL, DATA_LEN, encrypted, &encrypted_buffer_len);

    zassert_equal(ret, CKR_ARGUMENTS_BAD, "C_Encrypt did not fail on NULL pData");
}

ZTEST(ul_pkcs11_unit_testsuite, test__encrypt__pEncryptedData_nullptr__returns_arguments_bad){
    uint8_t data[DATA_LEN] = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15};
    long unsigned int encrypted_buffer_len = ENCRYPTED_BUFFER_LEN;

    CK_RV ret = C_Encrypt(0, data, DATA_LEN, NULL, &encrypted_buffer_len);

    zassert_equal(ret, CKR_ARGUMENTS_BAD, "C_Encrypt did not fail on NULL pEncryptedData");
}

ZTEST(ul_pkcs11_unit_testsuite, test__encrypt__pulEncryptedDataLen_nullptr__returns_arguments_bad){
    uint8_t data[DATA_LEN] = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15};
    uint8_t encrypted[ENCRYPTED_BUFFER_LEN] = {0};

    CK_RV ret = C_Encrypt(0, data, DATA_LEN, encrypted, NULL);

    zassert_equal(ret, CKR_ARGUMENTS_BAD, "C_Encrypt did not fail on NULL pulEncryptedDataLen");
}

ZTEST(ul_pkcs11_unit_testsuite, test__encrypt__ulDataLen_zero__returns_arguments_bad){
    uint8_t data[DATA_LEN] = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15};
    uint8_t encrypted[ENCRYPTED_BUFFER_LEN] = {0};
    long unsigned int encrypted_buffer_len = ENCRYPTED_BUFFER_LEN;

    CK_RV ret = C_Encrypt(0, data, 0, encrypted, &encrypted_buffer_len);

    zassert_equal(ret, CKR_ARGUMENTS_BAD, "C_Encrypt did not fail on zero ulDataLen");
}

ZTEST(ul_pkcs11_unit_testsuite, test__decrypt_init__psa_cipher_decrypt_setup_fails__returns_function_failed){
    psa_cipher_decrypt_setup_fake.return_val = PSA_ERROR_COMMUNICATION_FAILURE;

    CK_RV ret = C_DecryptInit(0, NULL, 0);

    zassert_equal(ret, CKR_FUNCTION_FAILED, "C_DecryptInit did not fail");
    zassert_equal(psa_cipher_decrypt_setup_fake.call_count, 1, "psa_cipher_decrypt_setup not called");
}

ZTEST(ul_pkcs11_unit_testsuite, test__decrypt_init__psa_functions_succeed__returns_success){
    psa_cipher_decrypt_setup_fake.return_val = PSA_SUCCESS;

    manually_initialize_global_crypto_context();

    CK_RV ret = C_DecryptInit(0, NULL, 0);

    zassert_equal(ret, CKR_OK, "C_DecryptInit failed");

    zassert_equal(psa_cipher_decrypt_setup_fake.call_count, 1, "psa_cipher_decrypt_setup not called");

    zassert_equal(psa_cipher_decrypt_setup_fake.arg1_val, GLOBAL_KEY_ID, "psa_cipher_decrypt_setup called with wrong key ID");
    zassert_equal(psa_cipher_decrypt_setup_fake.arg2_val, PSA_ALG_CTR, "psa_cipher_decrypt_setup called with wrong algorithm");
}

ZTEST(ul_pkcs11_unit_testsuite, test__decrypt__psa_cipher_decrypt_fails__returns_function_failed){
    psa_cipher_decrypt_fake.return_val = PSA_ERROR_COMMUNICATION_FAILURE;

    manually_initialize_global_crypto_context();

    uint8_t encrypted[ENCRYPTED_BUFFER_LEN] = {0xAB, 0xCD, 0xEF};
    uint8_t data[DATA_LEN] = {0};

    uint8_t encrypted_safe[ENCRYPTED_BUFFER_LEN];
    memcpy(encrypted_safe, encrypted, sizeof(encrypted));

    long unsigned int data_buffer_len = sizeof(data);

    CK_RV ret = C_Decrypt(0, encrypted, sizeof(encrypted), data, &data_buffer_len);

    zassert_equal(ret, CKR_FUNCTION_FAILED, "C_Decrypt did not fail");
    zassert_equal(psa_cipher_decrypt_fake.call_count, 1, "psa_cipher_decrypt not called");

    zassert_mem_equal(data, (uint8_t[DATA_LEN]){0}, DATA_LEN, "Decrypted data unexpectedly written on fail");

    zassert_mem_equal(encrypted, encrypted_safe, sizeof(encrypted), "Input encrypted data was modified unexpectedly");
    zassert_equal(data_buffer_len, sizeof(data), "Decrypted buffer length was modified unexpectedly");
}

ZTEST(ul_pkcs11_unit_testsuite, test__decrypt__psa_cipher_decrypt_succeeds__returns_success){
    psa_cipher_decrypt_fake.custom_fake = psa_cipher_decrypt_fake_impl;

    manually_initialize_global_crypto_context();

    uint8_t encrypted[ENCRYPTED_BUFFER_LEN] = {0xAB, 0xCD, 0xEF};
    uint8_t data[DATA_LEN] = {0};

    uint8_t expected_data[DATA_LEN] = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10};

    uint8_t encrypted_safe[ENCRYPTED_BUFFER_LEN];
    memcpy(encrypted_safe, encrypted, sizeof(encrypted));

    long unsigned int data_buffer_len = sizeof(data);

    CK_RV ret = C_Decrypt(0, encrypted, sizeof(encrypted), data, &data_buffer_len);

    zassert_equal(ret, CKR_OK, "C_Decrypt did fail");

    zassert_mem_equal(data, expected_data, DATA_LEN, "Decrypted data was not correctly written");
    zassert_equal(data_buffer_len, 11, "Decrypted buffer length was not set correctly");

    zassert_mem_equal(encrypted, encrypted_safe, sizeof(encrypted), "Input encrypted data was modified unexpectedly");

    zassert_equal(psa_cipher_decrypt_fake.call_count, 1, "psa_cipher_decrypt not called");
    zassert_equal(psa_cipher_decrypt_fake.arg0_val, GLOBAL_KEY_ID, "psa_cipher_decrypt called with wrong key ID");
    zassert_equal(psa_cipher_decrypt_fake.arg1_val, PSA_ALG_CTR, "psa_cipher_decrypt called with wrong algorithm");
    zassert_equal_ptr(psa_cipher_decrypt_fake.arg2_val, (uintptr_t)encrypted, "psa_cipher_decrypt called with wrong encrypted data pointer");
    zassert_equal(psa_cipher_decrypt_fake.arg3_val, sizeof(encrypted), "psa_cipher_decrypt called with wrong encrypted data length");
    zassert_equal_ptr(psa_cipher_decrypt_fake.arg4_val, (uintptr_t)data, "psa_cipher_decrypt called with wrong data pointer");
    zassert_equal(psa_cipher_decrypt_fake.arg5_val, DATA_LEN, "psa_cipher_decrypt called with wrong data buffer length");
    zassert_equal_ptr(psa_cipher_decrypt_fake.arg6_val, (uintptr_t)&data_buffer_len, "psa_cipher_decrypt called with wrong data length pointer");
}

ZTEST_SUITE(ul_pkcs11_unit_testsuite, NULL, NULL, setup_before_test_fixture, NULL, NULL);
