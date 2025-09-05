# SPDX-FileCopyrightText: 2025 UL Solutions - Software Intensive Systems
#
# SPDX-License-Identifier: Apache-2.0

add_library(ul_common_lib_flags INTERFACE)
target_compile_options(ul_common_lib_flags INTERFACE
    -Werror -Wall -Wextra
    -Wformat -Wformat=2 -Wimplicit-fallthrough
    -Werror=format-security -Werror=implicit -Werror=incompatible-pointer-types -Werror=int-conversion
    -U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=3
    -fno-delete-null-pointer-checks
)

add_subdirectory_ifdef(CONFIG_UL_PKCS11_IMPL pkcs11)
