// SPDX-License-Identifier: MIT
// Copyright (c) 2024 Logln Contributors

#pragma once

// ============================================================================
// Platform Detection
// ============================================================================

// Windows
#if defined(_WIN32) || defined(_WIN64) || defined(__CYGWIN__)
    #define LOGLN_PLATFORM_WINDOWS 1
    #define LOGLN_PLATFORM_NAME "Windows"
#endif

// Apple platforms
#if defined(__APPLE__) && defined(__MACH__)
    #include <TargetConditionals.h>
    
    #if TARGET_OS_IPHONE
        #if TARGET_OS_SIMULATOR
            #define LOGLN_PLATFORM_IOS_SIMULATOR 1
        #endif
        #define LOGLN_PLATFORM_IOS 1
        #define LOGLN_PLATFORM_NAME "iOS"
    #elif TARGET_OS_TV
        #define LOGLN_PLATFORM_TVOS 1
        #define LOGLN_PLATFORM_NAME "tvOS"
    #elif TARGET_OS_WATCH
        #define LOGLN_PLATFORM_WATCHOS 1
        #define LOGLN_PLATFORM_NAME "watchOS"
    #elif TARGET_OS_MAC
        #define LOGLN_PLATFORM_MACOS 1
        #define LOGLN_PLATFORM_NAME "macOS"
    #endif
    
    #define LOGLN_PLATFORM_APPLE 1
#endif

// Android
#if defined(__ANDROID__)
    #define LOGLN_PLATFORM_ANDROID 1
    #define LOGLN_PLATFORM_NAME "Android"
#endif

// HarmonyOS
#if defined(__OHOS__) || defined(OHOS)
    #define LOGLN_PLATFORM_HARMONYOS 1
    #define LOGLN_PLATFORM_NAME "HarmonyOS"
#endif

// Linux (after Android check, since Android also defines __linux__)
#if defined(__linux__) && !defined(__ANDROID__) && !defined(__OHOS__)
    #define LOGLN_PLATFORM_LINUX 1
    #define LOGLN_PLATFORM_NAME "Linux"
#endif

// FreeBSD
#if defined(__FreeBSD__)
    #define LOGLN_PLATFORM_FREEBSD 1
    #define LOGLN_PLATFORM_NAME "FreeBSD"
#endif

// Fallback
#ifndef LOGLN_PLATFORM_NAME
    #define LOGLN_PLATFORM_UNKNOWN 1
    #define LOGLN_PLATFORM_NAME "Unknown"
#endif

// ============================================================================
// Platform Groups
// ============================================================================

// POSIX-like systems
#if defined(LOGLN_PLATFORM_LINUX) || defined(LOGLN_PLATFORM_APPLE) || \
    defined(LOGLN_PLATFORM_ANDROID) || defined(LOGLN_PLATFORM_FREEBSD)
    #define LOGLN_PLATFORM_POSIX 1
#endif

// Mobile platforms
#if defined(LOGLN_PLATFORM_IOS) || defined(LOGLN_PLATFORM_ANDROID) || \
    defined(LOGLN_PLATFORM_HARMONYOS) || defined(LOGLN_PLATFORM_WATCHOS) || \
    defined(LOGLN_PLATFORM_TVOS)
    #define LOGLN_PLATFORM_MOBILE 1
#endif

// Desktop platforms
#if defined(LOGLN_PLATFORM_WINDOWS) || defined(LOGLN_PLATFORM_MACOS) || \
    defined(LOGLN_PLATFORM_LINUX) || defined(LOGLN_PLATFORM_FREEBSD)
    #define LOGLN_PLATFORM_DESKTOP 1
#endif

// ============================================================================
// Architecture Detection
// ============================================================================

#if defined(__x86_64__) || defined(_M_X64) || defined(__amd64__)
    #define LOGLN_ARCH_X64 1
    #define LOGLN_ARCH_NAME "x86_64"
#elif defined(__i386__) || defined(_M_IX86)
    #define LOGLN_ARCH_X86 1
    #define LOGLN_ARCH_NAME "x86"
#elif defined(__aarch64__) || defined(_M_ARM64)
    #define LOGLN_ARCH_ARM64 1
    #define LOGLN_ARCH_NAME "arm64"
#elif defined(__arm__) || defined(_M_ARM)
    #define LOGLN_ARCH_ARM 1
    #define LOGLN_ARCH_NAME "arm"
#elif defined(__riscv) && __riscv_xlen == 64
    #define LOGLN_ARCH_RISCV64 1
    #define LOGLN_ARCH_NAME "riscv64"
#elif defined(__riscv) && __riscv_xlen == 32
    #define LOGLN_ARCH_RISCV32 1
    #define LOGLN_ARCH_NAME "riscv32"
#else
    #define LOGLN_ARCH_UNKNOWN 1
    #define LOGLN_ARCH_NAME "Unknown"
#endif

// 64-bit detection
#if defined(LOGLN_ARCH_X64) || defined(LOGLN_ARCH_ARM64) || defined(LOGLN_ARCH_RISCV64)
    #define LOGLN_ARCH_64BIT 1
#else
    #define LOGLN_ARCH_32BIT 1
#endif

// ============================================================================
// Compiler Detection
// ============================================================================

#if defined(__clang__)
    #define LOGLN_COMPILER_CLANG 1
    #define LOGLN_COMPILER_NAME "Clang"
    #define LOGLN_COMPILER_VERSION (__clang_major__ * 10000 + __clang_minor__ * 100 + __clang_patchlevel__)
#elif defined(__GNUC__)
    #define LOGLN_COMPILER_GCC 1
    #define LOGLN_COMPILER_NAME "GCC"
    #define LOGLN_COMPILER_VERSION (__GNUC__ * 10000 + __GNUC_MINOR__ * 100 + __GNUC_PATCHLEVEL__)
#elif defined(_MSC_VER)
    #define LOGLN_COMPILER_MSVC 1
    #define LOGLN_COMPILER_NAME "MSVC"
    #define LOGLN_COMPILER_VERSION _MSC_VER
#else
    #define LOGLN_COMPILER_UNKNOWN 1
    #define LOGLN_COMPILER_NAME "Unknown"
    #define LOGLN_COMPILER_VERSION 0
#endif

// ============================================================================
// Feature Detection
// ============================================================================

// C++23 std::format support
#if defined(__cpp_lib_format) && __cpp_lib_format >= 202110L
    #define LOGLN_HAS_STD_FORMAT 1
#endif

// C++23 std::expected support
#if defined(__cpp_lib_expected) && __cpp_lib_expected >= 202202L
    #define LOGLN_HAS_STD_EXPECTED 1
#endif

// std::jthread support
#if defined(__cpp_lib_jthread) && __cpp_lib_jthread >= 201911L
    #define LOGLN_HAS_STD_JTHREAD 1
#endif

// std::source_location support
#if defined(__cpp_lib_source_location) && __cpp_lib_source_location >= 201907L
    #define LOGLN_HAS_SOURCE_LOCATION 1
#endif

// ============================================================================
// Export/Import Macros
// ============================================================================

#if defined(LOGLN_PLATFORM_WINDOWS)
    #ifdef LOGLN_BUILDING_DLL
        #define LOGLN_EXPORT __declspec(dllexport)
    #elif defined(LOGLN_USING_DLL)
        #define LOGLN_EXPORT __declspec(dllimport)
    #else
        #define LOGLN_EXPORT
    #endif
    #define LOGLN_HIDDEN
#else
    #if defined(__GNUC__) && __GNUC__ >= 4
        #define LOGLN_EXPORT __attribute__((visibility("default")))
        #define LOGLN_HIDDEN __attribute__((visibility("hidden")))
    #else
        #define LOGLN_EXPORT
        #define LOGLN_HIDDEN
    #endif
#endif

// ============================================================================
// Utility Macros
// ============================================================================

// Likely/Unlikely hints
#if defined(__GNUC__) || defined(__clang__)
    #define LOGLN_LIKELY(x)   __builtin_expect(!!(x), 1)
    #define LOGLN_UNLIKELY(x) __builtin_expect(!!(x), 0)
#else
    #define LOGLN_LIKELY(x)   (x)
    #define LOGLN_UNLIKELY(x) (x)
#endif

// Force inline
#if defined(_MSC_VER)
    #define LOGLN_FORCE_INLINE __forceinline
#elif defined(__GNUC__) || defined(__clang__)
    #define LOGLN_FORCE_INLINE __attribute__((always_inline)) inline
#else
    #define LOGLN_FORCE_INLINE inline
#endif

// No inline
#if defined(_MSC_VER)
    #define LOGLN_NOINLINE __declspec(noinline)
#elif defined(__GNUC__) || defined(__clang__)
    #define LOGLN_NOINLINE __attribute__((noinline))
#else
    #define LOGLN_NOINLINE
#endif

// Deprecated
#if defined(_MSC_VER)
    #define LOGLN_DEPRECATED(msg) __declspec(deprecated(msg))
#elif defined(__GNUC__) || defined(__clang__)
    #define LOGLN_DEPRECATED(msg) __attribute__((deprecated(msg)))
#else
    #define LOGLN_DEPRECATED(msg)
#endif

// Thread local
#if defined(_MSC_VER)
    #define LOGLN_THREAD_LOCAL __declspec(thread)
#else
    #define LOGLN_THREAD_LOCAL thread_local
#endif

// ============================================================================
// Platform-specific Includes
// ============================================================================

namespace logln::platform {

// Platform information
constexpr const char* name() noexcept { return LOGLN_PLATFORM_NAME; }
constexpr const char* arch() noexcept { return LOGLN_ARCH_NAME; }
constexpr const char* compiler() noexcept { return LOGLN_COMPILER_NAME; }

constexpr bool is_windows() noexcept {
#ifdef LOGLN_PLATFORM_WINDOWS
    return true;
#else
    return false;
#endif
}

constexpr bool is_apple() noexcept {
#ifdef LOGLN_PLATFORM_APPLE
    return true;
#else
    return false;
#endif
}

constexpr bool is_ios() noexcept {
#ifdef LOGLN_PLATFORM_IOS
    return true;
#else
    return false;
#endif
}

constexpr bool is_macos() noexcept {
#ifdef LOGLN_PLATFORM_MACOS
    return true;
#else
    return false;
#endif
}

constexpr bool is_android() noexcept {
#ifdef LOGLN_PLATFORM_ANDROID
    return true;
#else
    return false;
#endif
}

constexpr bool is_linux() noexcept {
#ifdef LOGLN_PLATFORM_LINUX
    return true;
#else
    return false;
#endif
}

constexpr bool is_harmonyos() noexcept {
#ifdef LOGLN_PLATFORM_HARMONYOS
    return true;
#else
    return false;
#endif
}

constexpr bool is_mobile() noexcept {
#ifdef LOGLN_PLATFORM_MOBILE
    return true;
#else
    return false;
#endif
}

constexpr bool is_desktop() noexcept {
#ifdef LOGLN_PLATFORM_DESKTOP
    return true;
#else
    return false;
#endif
}

constexpr bool is_posix() noexcept {
#ifdef LOGLN_PLATFORM_POSIX
    return true;
#else
    return false;
#endif
}

constexpr bool is_64bit() noexcept {
#ifdef LOGLN_ARCH_64BIT
    return true;
#else
    return false;
#endif
}

} // namespace logln::platform

// ============================================================================
// Platform Utility Functions (implemented in platform.cpp)
// ============================================================================

#include "types.hpp"

#include <cstdint>
#include <string>

namespace logln {

// Process/Thread ID
[[nodiscard]] std::int64_t get_pid() noexcept;
[[nodiscard]] std::int64_t get_tid() noexcept;
[[nodiscard]] std::int64_t get_main_tid() noexcept;

// Timestamps
[[nodiscard]] Timestamp get_timestamp() noexcept;
[[nodiscard]] std::uint64_t get_tick_count() noexcept;

} // namespace logln
