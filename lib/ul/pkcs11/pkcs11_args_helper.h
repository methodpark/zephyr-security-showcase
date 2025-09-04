#include <zephyr/logging/log.h>

#include <external/pkcs11/pkcs11.h>

#define CKR_CHECK_NULL(ptr)                   \
do {                                          \
    if ((ptr) == NULL) {                      \
        LOG_ERR(#ptr " is NULL");             \
        return CKR_ARGUMENTS_BAD;             \
    }                                         \
} while (0)

#define CKR_CHECK_ZERO(val)                   \
    do {                                      \
        if ((val) == 0) {                     \
            LOG_ERR(#val " is 0");            \
            return CKR_ARGUMENTS_BAD;         \
        }                                     \
    } while (0)
