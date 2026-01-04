# SPDX-License-Identifier: MIT
# Copyright (c) 2024 Logln Contributors
#
# Unit tests for logln library

# Google Test
FetchContent_Declare(
    googletest
    GIT_REPOSITORY https://github.com/google/googletest.git
    GIT_TAG        v1.17.0
)
# For Windows: Prevent overriding the parent project's compiler/linker settings
set(gtest_force_shared_crt ON CACHE BOOL "" FORCE)
FetchContent_MakeAvailable(googletest)

include(GoogleTest)

# ============================================================================
# Buffer Tests
# ============================================================================
add_executable(buffer_test 
    buffer_test.cpp
    ${CMAKE_SOURCE_DIR}/src/mmap_buffer.cpp
)
target_link_libraries(buffer_test
    PRIVATE
        GTest::gtest_main
        mio::mio
)
target_include_directories(buffer_test PRIVATE ${CMAKE_SOURCE_DIR}/src)
target_compile_features(buffer_test PRIVATE cxx_std_23)

gtest_discover_tests(buffer_test)

# ============================================================================
# Encryptor Tests
# ============================================================================
add_executable(encryptor_test 
    encryptor_test.cpp
    ${CMAKE_SOURCE_DIR}/src/chacha20_encryptor.cpp
)
target_link_libraries(encryptor_test
    PRIVATE
        GTest::gtest_main
        micro_ecc_lib
        monocypher_lib
)
target_include_directories(encryptor_test PRIVATE ${CMAKE_SOURCE_DIR}/src)
target_compile_features(encryptor_test PRIVATE cxx_std_23)

gtest_discover_tests(encryptor_test)

# ============================================================================
# Compressor Tests
# ============================================================================
add_executable(compressor_test 
    compressor_test.cpp
    ${CMAKE_SOURCE_DIR}/src/zstd_compressor.cpp
)
target_link_libraries(compressor_test
    PRIVATE
        GTest::gtest_main
        libzstd_static
)
target_include_directories(compressor_test PRIVATE ${CMAKE_SOURCE_DIR}/src)
target_compile_features(compressor_test PRIVATE cxx_std_23)

gtest_discover_tests(compressor_test)
