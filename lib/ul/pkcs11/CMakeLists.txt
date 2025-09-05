# SPDX-FileCopyrightText: 2025 UL Solutions - Software Intensive Systems
#
# SPDX-License-Identifier: Apache-2.0

zephyr_library()
zephyr_library_sources(pkcs11.c)

zephyr_library_link_libraries(ul_common_lib_flags)

zephyr_library_link_libraries(mbedTLS)