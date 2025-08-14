#include <zephyr/ztest.h>

#include <external/pkcs11/pkcs11.h>

ZTEST(ul_pkcs11_unit_testsuite, test__initialize__dummy_call)
{
    CK_RV ret = C_Initialize(NULL);

    zassert_equal(ret, CKR_OK, "C_Initialize failed");
}

ZTEST_SUITE(ul_pkcs11_unit_testsuite, NULL, NULL, NULL, NULL, NULL);
