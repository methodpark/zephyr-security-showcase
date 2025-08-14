#include <zephyr/ztest.h>

ZTEST(ul_pkcs11_unit_testsuite, test__dummy_add)
{
    zassert_equal(1+1, 2, "The math does not check out anymore?");
}

ZTEST_SUITE(ul_pkcs11_unit_testsuite, NULL, NULL, NULL, NULL, NULL);
