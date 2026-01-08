# SPDX-License-Identifier: MIT
# logln command-line tools

cmake_minimum_required(VERSION 3.20)

# ============================================================================
# loglnd - Log file decoder tool
# ============================================================================

add_executable(loglnd logln_decode.cpp)

# Static build: embed all decoder sources directly
target_sources(loglnd PRIVATE
    ${CMAKE_SOURCE_DIR}/src/decoder.cpp
    ${CMAKE_SOURCE_DIR}/src/log_buffer.cpp
    ${CMAKE_SOURCE_DIR}/src/mmap_buffer.cpp
    ${CMAKE_SOURCE_DIR}/src/zstd_compressor.cpp
    ${CMAKE_SOURCE_DIR}/src/chacha20_encryptor.cpp
    ${CMAKE_SOURCE_DIR}/src/utils.cpp
    ${monocypher_SOURCE_DIR}/src/monocypher.c
    ${micro_ecc_SOURCE_DIR}/uECC.c
)

target_link_libraries(loglnd PRIVATE libzstd_static mio::mio)

target_compile_definitions(loglnd PRIVATE uECC_CURVE=uECC_secp256k1)

# Include headers
target_include_directories(loglnd PRIVATE
    ${CMAKE_SOURCE_DIR}/include
    ${CMAKE_SOURCE_DIR}/src
    ${monocypher_SOURCE_DIR}/src
    ${micro_ecc_SOURCE_DIR}
)

target_compile_features(loglnd PRIVATE cxx_std_23)

# Platform-specific settings
if(WIN32)
    target_compile_definitions(loglnd PRIVATE
        WIN32_LEAN_AND_MEAN
        NOMINMAX
        _CRT_SECURE_NO_WARNINGS
    )
endif()

# Install
install(TARGETS loglnd
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
)

