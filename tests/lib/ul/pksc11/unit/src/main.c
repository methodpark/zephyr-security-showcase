#include <stdarg.h>
#include <zephyr/ztest.h>
#include <zephyr/fff.h>

#include <psa/crypto.h>
#include <psa/crypto_extra.h>

#include <external/pkcs11/pkcs11.h>

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

static void reset_fakes_fixture(void *f){
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

ZTEST_SUITE(ul_pkcs11_unit_testsuite, NULL, NULL, reset_fakes_fixture, NULL, NULL);
