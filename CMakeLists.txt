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
# Build Optimization
# ============================================================================

# Enable Link-Time Optimization only for shared library builds
include(CheckIPOSupported)
check_ipo_supported(RESULT IPO_SUPPORTED OUTPUT IPO_OUTPUT)
if(IPO_SUPPORTED AND LOGLN_BUILD_SHARED)
    set(CMAKE_INTERPROCEDURAL_OPTIMIZATION_RELEASE ON)
    set(CMAKE_INTERPROCEDURAL_OPTIMIZATION_RELWITHDEBINFO ON)
endif()

# Platform-specific Release optimization flags
if(MSVC)
    # Release optimization flags
    # /O2 is already set by CMake for Release, /Ob3 for more aggressive inlining
    string(REPLACE "/Ob2" "/Ob3" CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE}")
    string(REPLACE "/Ob2" "/Ob3" CMAKE_C_FLAGS_RELEASE "${CMAKE_C_FLAGS_RELEASE}")
else()
    # -O3 - Maximum optimization
    # -DNDEBUG - Disable assertions (already set by CMake)
    # -ffunction-sections -fdata-sections - Enable dead code elimination
    set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} -ffunction-sections -fdata-sections")
    set(CMAKE_C_FLAGS_RELEASE "${CMAKE_C_FLAGS_RELEASE} -ffunction-sections -fdata-sections")
    # --gc-sections - Remove unused sections at link time
    if(APPLE)
        set(CMAKE_EXE_LINKER_FLAGS_RELEASE "${CMAKE_EXE_LINKER_FLAGS_RELEASE} -Wl,-dead_strip")
        set(CMAKE_SHARED_LINKER_FLAGS_RELEASE "${CMAKE_SHARED_LINKER_FLAGS_RELEASE} -Wl,-dead_strip")
    else()
        set(CMAKE_EXE_LINKER_FLAGS_RELEASE "${CMAKE_EXE_LINKER_FLAGS_RELEASE} -Wl,--gc-sections")
        set(CMAKE_SHARED_LINKER_FLAGS_RELEASE "${CMAKE_SHARED_LINKER_FLAGS_RELEASE} -Wl,--gc-sections")
    endif()
endif()

# ============================================================================
# Options
# ============================================================================
option(LOGLN_BUILD_SHARED "Build shared library" OFF)
option(LOGLN_BUILD_TESTS "Build unit tests" ON)
option(LOGLN_BUILD_EXAMPLES "Build examples" OFF)


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

# zstd - Compression library
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
set(ZSTD_MULTITHREAD_SUPPORT OFF CACHE BOOL "" FORCE)
set(ZSTD_LEGACY_SUPPORT OFF CACHE BOOL "" FORCE)
FetchContent_MakeAvailable(zstd)

# micro-ecc for ECDH
FetchContent_Declare(
    micro_ecc
    GIT_REPOSITORY https://github.com/kmackay/micro-ecc.git
    GIT_TAG        v1.1
)
FetchContent_MakeAvailable(micro_ecc)

# Create micro_ecc library target for tests
add_library(micro_ecc_lib STATIC ${micro_ecc_SOURCE_DIR}/uECC.c)
target_include_directories(micro_ecc_lib PUBLIC ${micro_ecc_SOURCE_DIR})
target_compile_definitions(micro_ecc_lib PUBLIC uECC_CURVE=uECC_secp256k1)

# Monocypher for ChaCha20 symmetric encryption
FetchContent_Declare(
    monocypher
    GIT_REPOSITORY https://github.com/LoupVaillant/Monocypher.git
    GIT_TAG        4.0.2
)
FetchContent_MakeAvailable(monocypher)

# Create monocypher library target for tests
add_library(monocypher_lib STATIC ${monocypher_SOURCE_DIR}/src/monocypher.c)
target_include_directories(monocypher_lib PUBLIC ${monocypher_SOURCE_DIR}/src)

# concurrentqueue - High-performance lock-free queue
FetchContent_Declare(
    concurrentqueue
    GIT_REPOSITORY https://github.com/cameron314/concurrentqueue.git
    GIT_TAG        v1.0.4
)
FetchContent_MakeAvailable(concurrentqueue)

# Threads
find_package(Threads REQUIRED)

# ============================================================================
# Main Library (logln)
# ============================================================================

set(LOGLN_SOURCES
    src/logger.cpp
    src/appender.cpp
    src/async_worker.cpp
    src/file_sink.cpp
    src/console_sink.cpp
    src/formatter.cpp
    src/log_buffer.cpp
    src/mmap_buffer.cpp
    src/zstd_compressor.cpp
    src/chacha20_encryptor.cpp
    src/platform.cpp
    src/utils.cpp
    src/logln.cpp
)

set(LOGLN_PUBLIC_HEADERS
    include/logln/logln.h
    include/logln/logger.hpp
    include/logln/config.hpp
    include/logln/types.hpp
    include/logln/formatter.hpp
    include/logln/platform.hpp
)

# Choose library type based on option
if(LOGLN_BUILD_SHARED)
    # Shared library: embed small dependencies directly to avoid export issues
    add_library(logln SHARED 
        ${LOGLN_SOURCES}
        ${monocypher_SOURCE_DIR}/src/monocypher.c
        ${micro_ecc_SOURCE_DIR}/uECC.c
    )
    target_compile_definitions(logln PRIVATE 
        LOGLN_BUILDING_DLL
        uECC_CURVE=uECC_secp256k1
    )
    target_compile_definitions(logln INTERFACE LOGLN_USING_DLL)
    target_include_directories(logln PRIVATE
        ${monocypher_SOURCE_DIR}/src
        ${micro_ecc_SOURCE_DIR}
    )
    set_target_properties(logln PROPERTIES
        VERSION ${PROJECT_VERSION}
        SOVERSION ${PROJECT_VERSION_MAJOR}
    )
    # Link zstd statically into the shared library
    target_link_libraries(logln PRIVATE libzstd_static)
else()
    # Static library: embed sources directly (same as shared) for simpler export
    add_library(logln STATIC 
        ${LOGLN_SOURCES}
        ${monocypher_SOURCE_DIR}/src/monocypher.c
        ${micro_ecc_SOURCE_DIR}/uECC.c
    )
    target_compile_definitions(logln PRIVATE uECC_CURVE=uECC_secp256k1)
    target_include_directories(logln PRIVATE
        ${monocypher_SOURCE_DIR}/src
        ${micro_ecc_SOURCE_DIR}
    )
    target_link_libraries(logln PRIVATE libzstd_static)
endif()

# Also create an alias for consistent usage
add_library(logln::logln ALIAS logln)

target_include_directories(logln
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        $<INSTALL_INTERFACE:include>
    PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/src
        ${concurrentqueue_SOURCE_DIR}
)

target_link_libraries(logln
    PRIVATE
        mio::mio
        Threads::Threads
)

target_compile_features(logln PUBLIC cxx_std_23)

# Platform-specific settings
if(WIN32)
    target_compile_definitions(logln PRIVATE
        WIN32_LEAN_AND_MEAN
        NOMINMAX
        _CRT_SECURE_NO_WARNINGS
    )
endif()

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

# Android
if(ANDROID)
    target_link_libraries(logln PRIVATE log)
endif()

# ============================================================================
# Decoder Library (standalone shared library for third-party tools)
# ============================================================================
option(LOGLN_BUILD_DECODER_LIB "Build standalone decoder library" ON)
option(LOGLN_BUILD_TOOLS "Build command-line tools" ON)

if(LOGLN_BUILD_DECODER_LIB)
    # Decoder library sources - minimal set for decoding only
    set(LOGLN_DECODER_SOURCES
        src/decoder.cpp
        src/log_buffer.cpp
        src/mmap_buffer.cpp
        src/zstd_compressor.cpp
        src/chacha20_encryptor.cpp
        src/utils.cpp
        ${monocypher_SOURCE_DIR}/src/monocypher.c
        ${micro_ecc_SOURCE_DIR}/uECC.c
    )
    
    # Build decoder as shared library
    add_library(logln_decoder SHARED ${LOGLN_DECODER_SOURCES})
    
    target_compile_definitions(logln_decoder PRIVATE 
        LOGLN_DECODER_BUILDING_DLL
        uECC_CURVE=uECC_secp256k1
    )
    target_compile_definitions(logln_decoder INTERFACE LOGLN_DECODER_USING_DLL)
    
    target_include_directories(logln_decoder
        PUBLIC
            $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
            $<INSTALL_INTERFACE:include>
        PRIVATE
            ${CMAKE_CURRENT_SOURCE_DIR}/src
            ${monocypher_SOURCE_DIR}/src
            ${micro_ecc_SOURCE_DIR}
    )
    
    target_link_libraries(logln_decoder PRIVATE 
        libzstd_static
        mio::mio
    )
    
    target_compile_features(logln_decoder PUBLIC cxx_std_23)
    
    set_target_properties(logln_decoder PROPERTIES
        VERSION ${PROJECT_VERSION}
        SOVERSION ${PROJECT_VERSION_MAJOR}
        OUTPUT_NAME "logln_decoder"
    )
    
    # Platform-specific settings for decoder
    if(WIN32)
        target_compile_definitions(logln_decoder PRIVATE
            WIN32_LEAN_AND_MEAN
            NOMINMAX
            _CRT_SECURE_NO_WARNINGS
        )
    endif()
    
    # Also create alias for consistent usage
    add_library(logln::decoder ALIAS logln_decoder)
    
    # Install decoder library
    install(TARGETS logln_decoder
        EXPORT loglnDecoderTargets
        LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
        ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
        RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
        INCLUDES DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
    )
endif()

# ============================================================================
# Command-line Tools
# ============================================================================
if(LOGLN_BUILD_TOOLS)
    add_subdirectory(tools)
endif()

# ============================================================================
# Installation
# ============================================================================
include(GNUInstallDirs)
include(CMakePackageConfigHelpers)

install(TARGETS logln
    EXPORT loglnTargets
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
    INCLUDES DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
)

install(DIRECTORY include/logln
    DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
    FILES_MATCHING PATTERN "*.h" PATTERN "*.hpp"
)

install(EXPORT loglnTargets
    FILE loglnTargets.cmake
    NAMESPACE logln::
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/logln
)

configure_package_config_file(
    ${CMAKE_CURRENT_SOURCE_DIR}/cmake/loglnConfig.cmake.in
    ${CMAKE_CURRENT_BINARY_DIR}/loglnConfig.cmake
    INSTALL_DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/logln
)

write_basic_package_version_file(
    ${CMAKE_CURRENT_BINARY_DIR}/loglnConfigVersion.cmake
    VERSION ${PROJECT_VERSION}
    COMPATIBILITY SameMajorVersion
)

install(FILES
    ${CMAKE_CURRENT_BINARY_DIR}/loglnConfig.cmake
    ${CMAKE_CURRENT_BINARY_DIR}/loglnConfigVersion.cmake
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/logln
)


# ============================================================================
# Examples
# ============================================================================

if(LOGLN_BUILD_EXAMPLES)
    add_subdirectory(examples)
endif()

# ============================================================================
# Testing
# ============================================================================

if(LOGLN_BUILD_TESTS)
    enable_testing()
    add_subdirectory(tests)
endif()
