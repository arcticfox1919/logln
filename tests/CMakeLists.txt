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
