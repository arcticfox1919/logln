cmake_minimum_required(VERSION 3.20)
project(logln 
    VERSION 1.0.0
    DESCRIPTION "Modern C++23 high-performance logging library"
    LANGUAGES CXX C
)

# ============================================================================
# C++ Standard
# ============================================================================
set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# ============================================================================
# Options
# ============================================================================


# ============================================================================
# Dependencies
# ============================================================================
include(FetchContent)

# mio - Cross-platform memory-mapped IO
FetchContent_Declare(
    mio
    GIT_REPOSITORY https://github.com/vimpunk/mio.git
    GIT_TAG        master
)
FetchContent_MakeAvailable(mio)

# zstd - Always needed for decoder library, optional for main library
# (decoder needs to be able to decode any log file)
find_package(zstd QUIET)
if(NOT zstd_FOUND)
    FetchContent_Declare(
        zstd
        GIT_REPOSITORY https://github.com/facebook/zstd.git
        GIT_TAG        v1.5.7
        SOURCE_SUBDIR  build/cmake
    )
    set(ZSTD_BUILD_PROGRAMS OFF CACHE BOOL "" FORCE)
    set(ZSTD_BUILD_TESTS OFF CACHE BOOL "" FORCE)
    set(ZSTD_BUILD_SHARED OFF CACHE BOOL "" FORCE)
    set(ZSTD_BUILD_STATIC ON CACHE BOOL "" FORCE)
    FetchContent_MakeAvailable(zstd)
endif()

# micro-ecc for ECDH - Always needed for decoder library
FetchContent_Declare(
    micro_ecc
    GIT_REPOSITORY https://github.com/kmackay/micro-ecc.git
    GIT_TAG        v1.1
)
FetchContent_MakeAvailable(micro_ecc)

# micro-ecc is header + source, create a static library
add_library(micro_ecc_lib STATIC
    ${micro_ecc_SOURCE_DIR}/uECC.c
)
target_include_directories(micro_ecc_lib PUBLIC
    ${micro_ecc_SOURCE_DIR}
)
# Use secp256k1 curve
target_compile_definitions(micro_ecc_lib PRIVATE uECC_CURVE=uECC_secp256k1)

# ============================================================================
# Main Library (logln)
# ============================================================================

# ============================================================================
# Library
# ============================================================================



# Apple platforms (iOS, macOS, watchOS, tvOS)
if(APPLE)
    # Link Foundation framework for NSLog
    target_link_libraries(logln PRIVATE "-framework Foundation")
    
    # Detect iOS vs macOS
    if(CMAKE_SYSTEM_NAME STREQUAL "iOS")
        target_compile_definitions(logln PRIVATE LOGLN_IOS=1)
    elseif(CMAKE_SYSTEM_NAME STREQUAL "Darwin")
        target_compile_definitions(logln PRIVATE LOGLN_MACOS=1)
    endif()
    
    # Enable Objective-C++ for console_sink.cpp to use NSLog
    set_source_files_properties(src/console_sink.cpp
        PROPERTIES COMPILE_FLAGS "-x objective-c++"
    )
endif()


# ============================================================================
# Testing
# ============================================================================
option(LOGLN_BUILD_TESTS "Build unit tests" ON)

if(LOGLN_BUILD_TESTS)
    enable_testing()
    add_subdirectory(tests)
endif()
