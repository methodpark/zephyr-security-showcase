cmake_minimum_required(VERSION 3.20.0)

find_package(Zephyr COMPONENTS unittest REQUIRED HINTS $ENV{ZEPHYR_BASE})

project(ul_pkcs11_unittest)

target_include_directories(testbinary PRIVATE
        ${ZEPHYR_UL_ZEPHYR_SECURITY_SHOWCASE_MODULE_DIR}/include
        ${ZEPHYR_UL_ZEPHYR_SECURITY_SHOWCASE_MODULE_DIR}/lib/ul/pkcs11/
        ${ZEPHYR_BASE}/../modules/crypto/mbedtls/include
)

target_sources(testbinary PRIVATE
    src/main.c
)

target_compile_options(testbinary PRIVATE -include zephyr/ztest.h)

target_sources(testbinary PRIVATE
        ${ZEPHYR_UL_ZEPHYR_SECURITY_SHOWCASE_MODULE_DIR}/lib/ul/pkcs11/pkcs11.c
)
