// SPDX-License-Identifier: MIT
// Copyright (c) 2024 Logln Contributors

/**
 * @file logln.h
 * @brief Logln - High-performance logging library
 * 
 * This header provides both C and C++ APIs for the Logln logging library.
 * The C API is designed for cross-language FFI bindings (Java/JNI, Swift, Python, Rust, etc.)
 * 
 * C Usage:
 * @code
 * logln_config_t config = logln_config_create();
 * logln_config_set_log_dir(config, "/path/to/logs");
 * logln_config_set_name(config, "myapp");
 * 
 * logln_handle_t logger = logln_create(config);
 * logln_config_destroy(config);
 * 
 * LOGLN_INFO(logger, "Network", "Connected to %s:%d", host, port);
 * logln_release(logger);
 * @endcode
 */

#ifndef LOGLN_H
#define LOGLN_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <stdarg.h>

// ============================================================================
// Export Macros
// ============================================================================

#if defined(_WIN32) || defined(_WIN64)
    #ifdef LOGLN_BUILDING_DLL
        #define LOGLN_API __declspec(dllexport)
    #elif defined(LOGLN_USING_DLL)
        #define LOGLN_API __declspec(dllimport)
    #else
        #define LOGLN_API
    #endif
#else
    #if __GNUC__ >= 4 || defined(__clang__)
        #define LOGLN_API __attribute__((visibility("default")))
    #else
        #define LOGLN_API
    #endif
#endif

#ifdef __cplusplus
extern "C" {
#endif

// ============================================================================
// C API - Types
// ============================================================================

typedef enum logln_level {
    LOGLN_LEVEL_VERBOSE = 0,
    LOGLN_LEVEL_DEBUG   = 1,
    LOGLN_LEVEL_INFO    = 2,
    LOGLN_LEVEL_WARN    = 3,
    LOGLN_LEVEL_ERROR   = 4,
    LOGLN_LEVEL_FATAL   = 5,
    LOGLN_LEVEL_OFF     = 6
} logln_level_t;

typedef enum logln_write_mode {
    LOGLN_MODE_ASYNC = 0,
    LOGLN_MODE_SYNC  = 1
} logln_write_mode_t;

typedef enum logln_compression {
    LOGLN_COMPRESS_NONE = 0,
    LOGLN_COMPRESS_ZSTD = 1
} logln_compression_t;

typedef void* logln_config_t;
typedef void* logln_handle_t;

typedef enum logln_result {
    LOGLN_OK                        =  0,
    LOGLN_ERROR_INVALID             = -1,
    LOGLN_ERROR_NOT_INIT            = -2,
    LOGLN_ERROR_ALREADY             = -3,
    LOGLN_ERROR_NOT_FOUND           = -4,
    LOGLN_ERROR_IO                  = -5,
    LOGLN_ERROR_MEMORY              = -6,
    LOGLN_ERROR_EMPTY_LOG_DIR       = -10,
    LOGLN_ERROR_EMPTY_NAME_PREFIX   = -11,
    LOGLN_ERROR_INVALID_NAME_PREFIX = -12,
    LOGLN_ERROR_INVALID_COMPRESS_LV = -13,
    LOGLN_ERROR_INVALID_FLUSH_INT   = -14,
    LOGLN_ERROR_INVALID_ALIVE_TIME  = -15,
    LOGLN_ERROR_INVALID_CACHE_DAYS  = -16,
    LOGLN_ERROR_LOG_DIR_NOT_WRITABLE= -17,
    LOGLN_ERROR_CACHE_DIR_NOT_WRITABLE=-18
} logln_result_t;

typedef struct logln_config_options {
    const char*         log_dir;
    const char*         cache_dir;
    const char*         name;
    const char*         format;
    logln_level_t       min_level;
    logln_write_mode_t  mode;
    logln_compression_t compression;
    int                 compression_level;
    const char*         pub_key;
    uint64_t            max_file_size;
    int64_t             max_alive_seconds;
    int32_t             flush_interval_ms;
    int32_t             cache_days;
    bool                console_output;
    uint8_t             _reserved[3];
} logln_config_options_t;

#define LOGLN_CONFIG_OPTIONS_INIT { \
    .log_dir = NULL,                \
    .cache_dir = NULL,              \
    .name = NULL,                   \
    .format = NULL,                 \
    .min_level = LOGLN_LEVEL_INFO,  \
    .mode = LOGLN_MODE_ASYNC,       \
    .compression = LOGLN_COMPRESS_NONE, \
    .compression_level = 3,         \
    .pub_key = NULL,                \
    .max_file_size = 0,             \
    .max_alive_seconds = 24 * 60 * 60 * 10, \
    .flush_interval_ms = 15 * 60 * 1000,    \
    .cache_days = 0,                \
    .console_output = false,        \
    ._reserved = {0, 0, 0}          \
}

// ============================================================================
// C API - Error Handling
// ============================================================================

LOGLN_API const char* logln_result_message(logln_result_t result);

// ============================================================================
// C API - Configuration
// ============================================================================

LOGLN_API logln_config_t logln_config_create(void);
LOGLN_API void logln_config_destroy(logln_config_t config);
LOGLN_API logln_result_t logln_config_set_log_dir(logln_config_t config, const char* path);
LOGLN_API logln_result_t logln_config_set_cache_dir(logln_config_t config, const char* path);
LOGLN_API logln_result_t logln_config_set_name(logln_config_t config, const char* name);
LOGLN_API logln_result_t logln_config_set_mode(logln_config_t config, logln_write_mode_t mode);
LOGLN_API logln_result_t logln_config_set_compression(logln_config_t config, logln_compression_t compression, int level);
LOGLN_API logln_result_t logln_config_set_pub_key(logln_config_t config, const char* pub_key);
LOGLN_API logln_result_t logln_config_set_max_file_size(logln_config_t config, uint64_t max_bytes);
LOGLN_API logln_result_t logln_config_set_max_alive_duration(logln_config_t config, int64_t seconds);
LOGLN_API logln_result_t logln_config_set_console_output(logln_config_t config, bool enable);
LOGLN_API logln_result_t logln_config_set_min_level(logln_config_t config, logln_level_t level);
LOGLN_API logln_result_t logln_config_set_format(logln_config_t config, const char* pattern);
LOGLN_API logln_result_t logln_config_validate(logln_config_t config);
LOGLN_API int logln_config_validate_all(logln_config_t config, logln_result_t* errors, int max_errors);

// ============================================================================
// C API - Logger Lifecycle
// ============================================================================

LOGLN_API logln_handle_t logln_create(logln_config_t config);
LOGLN_API logln_handle_t logln_create_with_options(const logln_config_options_t* options);
LOGLN_API logln_result_t logln_validate_options(const logln_config_options_t* options);

typedef void (*logln_create_callback_t)(logln_handle_t handle, bool success, void* user_data);
LOGLN_API logln_result_t logln_create_async(logln_config_t config, logln_create_callback_t callback, void* user_data);

LOGLN_API logln_handle_t logln_get(const char* name);
LOGLN_API bool logln_exists(const char* name);
LOGLN_API logln_result_t logln_release(logln_handle_t handle);
LOGLN_API logln_result_t logln_release_by_name(const char* name);
LOGLN_API void logln_release_all(void);
LOGLN_API size_t logln_count(void);

// ============================================================================
// C API - Logging Functions
// ============================================================================

LOGLN_API bool logln_is_enabled(logln_handle_t handle, logln_level_t level);

LOGLN_API void logln_write(logln_handle_t handle,
                           logln_level_t level,
                           const char* tag,
                           const char* file,
                           int line,
                           const char* func,
                           const char* fmt, ...)
#if defined(__GNUC__) || defined(__clang__)
    __attribute__((format(printf, 7, 8)))
#endif
;

LOGLN_API void logln_write_v(logln_handle_t handle,
                             logln_level_t level,
                             const char* tag,
                             const char* file,
                             int line,
                             const char* func,
                             const char* fmt,
                             va_list args);

#define LOGLN_VERBOSE(h, tag, fmt, ...) \
    logln_write(h, LOGLN_LEVEL_VERBOSE, tag, __FILE__, __LINE__, __func__, fmt, ##__VA_ARGS__)
#define LOGLN_DEBUG(h, tag, fmt, ...) \
    logln_write(h, LOGLN_LEVEL_DEBUG, tag, __FILE__, __LINE__, __func__, fmt, ##__VA_ARGS__)
#define LOGLN_INFO(h, tag, fmt, ...) \
    logln_write(h, LOGLN_LEVEL_INFO, tag, __FILE__, __LINE__, __func__, fmt, ##__VA_ARGS__)
#define LOGLN_WARN(h, tag, fmt, ...) \
    logln_write(h, LOGLN_LEVEL_WARN, tag, __FILE__, __LINE__, __func__, fmt, ##__VA_ARGS__)
#define LOGLN_ERROR(h, tag, fmt, ...) \
    logln_write(h, LOGLN_LEVEL_ERROR, tag, __FILE__, __LINE__, __func__, fmt, ##__VA_ARGS__)
#define LOGLN_FATAL(h, tag, fmt, ...) \
    logln_write(h, LOGLN_LEVEL_FATAL, tag, __FILE__, __LINE__, __func__, fmt, ##__VA_ARGS__)

// ============================================================================
// C API - Logger Control
// ============================================================================

LOGLN_API logln_result_t logln_set_level(logln_handle_t handle, logln_level_t level);
LOGLN_API logln_level_t logln_get_level(logln_handle_t handle);
LOGLN_API logln_result_t logln_set_mode(logln_handle_t handle, logln_write_mode_t mode);
LOGLN_API logln_result_t logln_set_console_output(logln_handle_t handle, bool enable);
LOGLN_API logln_result_t logln_set_pattern(logln_handle_t handle, const char* pattern);
LOGLN_API logln_result_t logln_flush(logln_handle_t handle);
LOGLN_API logln_result_t logln_flush_sync(logln_handle_t handle);
LOGLN_API logln_result_t logln_flush_all(bool sync);

// ============================================================================
// C API - File Management
// ============================================================================

LOGLN_API int logln_get_log_path(logln_handle_t handle, char* buffer, size_t buffer_size);
LOGLN_API int logln_get_cache_path(logln_handle_t handle, char* buffer, size_t buffer_size);
LOGLN_API int logln_get_all_log_files(logln_handle_t handle, char** paths, size_t path_buffer_size, size_t max_paths, bool include_current);
LOGLN_API size_t logln_remove_log_files(logln_handle_t handle, const char** paths, size_t count);

typedef void (*logln_remove_callback_t)(size_t removed_count, void* user_data);
LOGLN_API void logln_remove_log_files_async(logln_handle_t handle, const char** paths, size_t count, logln_remove_callback_t callback, void* user_data);
LOGLN_API size_t logln_remove_expired_log_files(logln_handle_t handle, int days_ago);
LOGLN_API void logln_remove_expired_log_files_async(logln_handle_t handle, int days_ago, logln_remove_callback_t callback, void* user_data);

// ============================================================================
// C API - Utilities
// ============================================================================

LOGLN_API const char* logln_version(void);
LOGLN_API int logln_version_number(void);
LOGLN_API const char* logln_level_to_string(logln_level_t level);
LOGLN_API logln_level_t logln_level_from_string(const char* str);

#ifdef __cplusplus
}
#endif

// ============================================================================
// C++ API
// ============================================================================

#ifdef __cplusplus

#include "types.hpp"
#include "config.hpp"
#include "formatter.hpp"
#include "logger.hpp"
#include "platform.hpp"

#endif // __cplusplus

#endif // LOGLN_H
