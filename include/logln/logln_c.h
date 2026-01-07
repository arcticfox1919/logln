// SPDX-License-Identifier: MIT
// Copyright (c) 2024 Logln Contributors

/**
 * @file logln_c.h
 * @brief C API for Logln - Cross-language FFI bindings
 * 
 * This header provides a pure C interface for using Logln from other languages
 * such as Java/Kotlin (JNI), Swift/Objective-C, Python (ctypes/cffi), Rust, etc.
 * 
 * Design:
 *   - All loggers are created via logln_create() with a config
 *   - The config's name determines the logger's unique name
 *   - Access loggers by handle (returned from create) or by name (via logln_get)
 * 
 * Usage:
 * @code
 * // Create config and logger
 * logln_config_t config = logln_config_create();
 * logln_config_set_log_dir(config, "/path/to/logs");
 * logln_config_set_name(config, "myapp");  // This is the logger name
 * 
 * logln_handle_t logger = logln_create(config);
 * logln_config_destroy(config);
 * 
 * // Log messages
 * LOGLN_INFO(logger, "Network", "Connected to %s:%d", host, port);
 * 
 * // Or get logger by name later
 * logln_handle_t same_logger = logln_get("myapp");
 * 
 * // Cleanup
 * logln_release(logger);
 * @endcode
 */

#ifndef LOGLN_C_H
#define LOGLN_C_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <stdarg.h>

#ifdef __cplusplus
extern "C" {
#endif

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

// ============================================================================
// Types
// ============================================================================

/**
 * @brief Log level enumeration
 */
typedef enum logln_level {
    LOGLN_LEVEL_VERBOSE = 0,
    LOGLN_LEVEL_DEBUG   = 1,
    LOGLN_LEVEL_INFO    = 2,
    LOGLN_LEVEL_WARN    = 3,
    LOGLN_LEVEL_ERROR   = 4,
    LOGLN_LEVEL_FATAL   = 5,
    LOGLN_LEVEL_OFF     = 6   /**< Disable all logging */
} logln_level_t;

/**
 * @brief Write mode enumeration
 */
typedef enum logln_write_mode {
    LOGLN_MODE_ASYNC = 0,  /**< Background thread write (default) */
    LOGLN_MODE_SYNC  = 1   /**< Immediate write */
} logln_write_mode_t;

/**
 * @brief Compression mode enumeration
 */
typedef enum logln_compression {
    LOGLN_COMPRESS_NONE = 0,
    LOGLN_COMPRESS_ZSTD = 1
} logln_compression_t;

/**
 * @brief Opaque handle for configuration
 */
typedef void* logln_config_t;

/**
 * @brief Opaque handle for logger instance
 */
typedef void* logln_handle_t;

/**
 * @brief Result code for operations
 */
typedef enum logln_result {
    LOGLN_OK                        =  0,
    LOGLN_ERROR_INVALID             = -1,  /**< Invalid parameter */
    LOGLN_ERROR_NOT_INIT            = -2,  /**< Logger not initialized */
    LOGLN_ERROR_ALREADY             = -3,  /**< Already exists (name collision) */
    LOGLN_ERROR_NOT_FOUND           = -4,  /**< Instance not found */
    LOGLN_ERROR_IO                  = -5,  /**< I/O error */
    LOGLN_ERROR_MEMORY              = -6,  /**< Memory allocation failed */
    
    // Configuration validation errors (mirrors ConfigError)
    LOGLN_ERROR_EMPTY_LOG_DIR       = -10, /**< log_dir is empty */
    LOGLN_ERROR_EMPTY_NAME_PREFIX   = -11, /**< name_prefix is empty */
    LOGLN_ERROR_INVALID_NAME_PREFIX = -12, /**< name_prefix has invalid chars */
    LOGLN_ERROR_INVALID_COMPRESS_LV = -13, /**< compression_level out of range */
    LOGLN_ERROR_INVALID_FLUSH_INT   = -14, /**< flush_interval too short */
    LOGLN_ERROR_INVALID_ALIVE_TIME  = -15, /**< max_alive_duration too short */
    LOGLN_ERROR_INVALID_CACHE_DAYS  = -16, /**< cache_days is negative */
    LOGLN_ERROR_LOG_DIR_NOT_WRITABLE= -17, /**< Cannot write to log_dir */
    LOGLN_ERROR_CACHE_DIR_NOT_WRITABLE=-18 /**< Cannot write to cache_dir */
} logln_result_t;

/**
 * @brief Configuration options structure for single-call setup
 * 
 * This structure allows setting all configuration options in a single FFI call,
 * which is more efficient for language bindings (Python, Java, C#, etc.).
 * 
 * Fields set to NULL/0 will use default values.
 * 
 * @example
 * ```c
 * logln_config_options_t opts = LOGLN_CONFIG_OPTIONS_INIT;
 * opts.log_dir = "./logs";
 * opts.name = "myapp";
 * opts.min_level = LOGLN_LEVEL_INFO;
 * opts.console_output = true;
 * 
 * logln_handle_t logger = logln_create_with_options(&opts);
 * ```
 */
typedef struct logln_config_options {
    const char*         log_dir;            /**< Log output directory (required) */
    const char*         cache_dir;          /**< Cache directory (optional, defaults to log_dir) */
    const char*         name;               /**< Logger name/prefix (required) */
    const char*         format;             /**< Log format pattern (optional, see logln_config_set_format) */
    logln_level_t       min_level;          /**< Minimum log level (default: INFO) */
    logln_write_mode_t  mode;               /**< Write mode (default: ASYNC) */
    logln_compression_t compression;        /**< Compression mode (default: NONE) */
    int                 compression_level;  /**< Compression level 1-22 (default: 3) */
    const char*         pub_key;            /**< Encryption public key (optional) */
    uint64_t            max_file_size;      /**< Max file size in bytes (default: 100MB) */
    int64_t             max_alive_seconds;  /**< Max log duration in seconds (default: 24h) */
    int32_t             flush_interval_ms;  /**< Flush interval in milliseconds (default: 15min) */
    int32_t             cache_days;         /**< Days to keep cached logs (default: 0) */
    bool                console_output;     /**< Enable console output (default: false) */
    uint8_t             _reserved[3];       /**< Padding for alignment */
} logln_config_options_t;

/**
 * @brief Initializer for logln_config_options_t with default values
 * 
 * Usage: logln_config_options_t opts = LOGLN_CONFIG_OPTIONS_INIT;
 */
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

/**
 * @brief Get human-readable error message
 * @param result Result code
 * @return Static string describing the error
 */
LOGLN_API const char* logln_result_message(logln_result_t result);

// ============================================================================
// Configuration API
// ============================================================================

/**
 * @brief Create a new configuration object with default values
 * @return Configuration handle, or NULL on failure
 */
LOGLN_API logln_config_t logln_config_create(void);

/**
 * @brief Destroy a configuration object
 * @param config Configuration handle
 */
LOGLN_API void logln_config_destroy(logln_config_t config);

/**
 * @brief Set the log output directory
 * @param config Configuration handle
 * @param path Directory path (UTF-8 encoded)
 * @return LOGLN_OK on success
 */
LOGLN_API logln_result_t logln_config_set_log_dir(logln_config_t config, const char* path);

/**
 * @brief Set the cache directory for temporary logs
 * @param config Configuration handle
 * @param path Directory path (UTF-8 encoded)
 * @return LOGLN_OK on success
 */
LOGLN_API logln_result_t logln_config_set_cache_dir(logln_config_t config, const char* path);

/**
 * @brief Set the logger name (also used as log file prefix)
 * @param config Configuration handle
 * @param name Logger name, must be unique (e.g., "network", "database")
 * @return LOGLN_OK on success
 * 
 * @note This name is used to:
 *   1. Identify the logger instance (for logln_get)
 *   2. Prefix log file names (e.g., "network_20241127.log")
 */
LOGLN_API logln_result_t logln_config_set_name(logln_config_t config, const char* name);

/**
 * @brief Set the write mode
 * @param config Configuration handle
 * @param mode Write mode (LOGLN_MODE_ASYNC or LOGLN_MODE_SYNC)
 * @return LOGLN_OK on success
 */
LOGLN_API logln_result_t logln_config_set_mode(logln_config_t config, logln_write_mode_t mode);

/**
 * @brief Set compression settings
 * @param config Configuration handle
 * @param compression Compression mode
 * @param level Compression level (1-22 for zstd)
 * @return LOGLN_OK on success
 */
LOGLN_API logln_result_t logln_config_set_compression(logln_config_t config, 
                                                       logln_compression_t compression,
                                                       int level);

/**
 * @brief Set encryption public key
 * @param config Configuration handle
 * @param pub_key Public key string (NULL to disable encryption)
 * @return LOGLN_OK on success
 */
LOGLN_API logln_result_t logln_config_set_pub_key(logln_config_t config, const char* pub_key);

/**
 * @brief Set maximum log file size
 * @param config Configuration handle
 * @param max_bytes Maximum size in bytes (0 = no limit)
 * @return LOGLN_OK on success
 */
LOGLN_API logln_result_t logln_config_set_max_file_size(logln_config_t config, uint64_t max_bytes);

/**
 * @brief Set maximum log retention time
 * @param config Configuration handle
 * @param seconds Maximum time in seconds (default: 10 days)
 * @return LOGLN_OK on success
 */
LOGLN_API logln_result_t logln_config_set_max_alive_duration(logln_config_t config, int64_t seconds);

/**
 * @brief Enable/disable console output
 * @param config Configuration handle
 * @param enable true to enable, false to disable
 * @return LOGLN_OK on success
 */
LOGLN_API logln_result_t logln_config_set_console_output(logln_config_t config, bool enable);

/**
 * @brief Set minimum log level
 * @param config Configuration handle
 * @param level Minimum level (logs below this are ignored)
 * @return LOGLN_OK on success
 */
LOGLN_API logln_result_t logln_config_set_min_level(logln_config_t config, logln_level_t level);

/**
 * @brief Set log format pattern
 * @param config Configuration handle
 * @param pattern Format pattern string. Supported tokens:
 *   - {level}  : Single letter level (D, I, W, E, F)
 *   - {Level}  : Full level name (DEBUG, INFO, WARN, ERROR, FATAL)
 *   - {time}   : Timestamp with timezone (YYYY-MM-DD +TZ HH:MM:SS.mmm)
 *   - {time6}  : Timestamp with 6-digit micros (YYYY-MM-DD HH:MM:SS.uuuuuu)
 *   - {date}   : Date only (YYYY-MM-DD)
 *   - {pid}    : Process ID
 *   - {tid}    : Thread ID
 *   - {tid*}   : Thread ID with * suffix if main thread
 *   - {tag}    : Log tag
 *   - {file}   : Source file name (without path)
 *   - {path}   : Full source file path
 *   - {line}   : Source line number
 *   - {func}   : Function name
 *   - {msg}    : Log message
 *   - {n}      : Newline
 * 
 * Example: "[{time6} | tag | {Level} | {tag}] {msg}{n}"
 * Output:  "[2025-12-02 14:28:35.584000 | tag | INFO | Main] Application started"
 * 
 * @return LOGLN_OK on success
 */
LOGLN_API logln_result_t logln_config_set_format(logln_config_t config, const char* pattern);

/**
 * @brief Validate configuration
 * @param config Configuration handle
 * @return LOGLN_OK if valid, or first validation error code
 * @note Use logln_config_validate_all() to get all errors
 */
LOGLN_API logln_result_t logln_config_validate(logln_config_t config);

/**
 * @brief Validate configuration and get all errors
 * @param config Configuration handle
 * @param errors Output array for error codes (can be NULL to just get count)
 * @param max_errors Maximum number of errors to store
 * @return Number of validation errors (0 = valid)
 */
LOGLN_API int logln_config_validate_all(logln_config_t config, 
                                         logln_result_t* errors, 
                                         int max_errors);

// ============================================================================
// Logger Lifecycle API
// ============================================================================

/**
 * @brief Create a logger instance
 * @param config Configuration handle (name is from config's name setting)
 * @return Logger handle, or NULL on failure (check errno or use validate first)
 * 
 * @warning This performs I/O (directory creation, mmap) and may block.
 *          On mobile/UI thread, use logln_create_async().
 * 
 * @note The logger name comes from logln_config_set_name(). If not set,
 *       defaults to "Logln".
 */
LOGLN_API logln_handle_t logln_create(logln_config_t config);

/**
 * @brief Create a logger with options structure (single FFI call)
 * @param options Pointer to configuration options structure
 * @return Logger handle, or NULL on failure
 * 
 * This is more efficient for FFI bindings as it requires only one
 * cross-language call instead of multiple logln_config_set_* calls.
 * 
 * @example (Python via ctypes)
 * ```python
 * opts = logln_config_options_t()
 * opts.log_dir = b"./logs"
 * opts.name = b"myapp"
 * opts.min_level = LOGLN_LEVEL_DEBUG
 * logger = lib.logln_create_with_options(ctypes.byref(opts))
 * ```
 */
LOGLN_API logln_handle_t logln_create_with_options(const logln_config_options_t* options);

/**
 * @brief Validate options structure without creating logger
 * @param options Pointer to configuration options structure
 * @return LOGLN_OK if valid, error code otherwise
 */
LOGLN_API logln_result_t logln_validate_options(const logln_config_options_t* options);

/**
 * @brief Callback for async logger creation
 * @param handle Created logger handle (NULL on failure)
 * @param success true if creation succeeded
 * @param user_data User-provided context
 */
typedef void (*logln_create_callback_t)(logln_handle_t handle, bool success, void* user_data);

/**
 * @brief Create a logger instance asynchronously (non-blocking)
 * @param config Configuration handle
 * @param callback Called when creation completes (from background thread)
 * @param user_data User context passed to callback
 * @return LOGLN_OK if async operation started
 * 
 * Safe to call from main/UI thread. Callback is invoked from a background
 * thread - use appropriate synchronization to update UI.
 */
LOGLN_API logln_result_t logln_create_async(logln_config_t config,
                                             logln_create_callback_t callback,
                                             void* user_data);

/**
 * @brief Get an existing logger by name
 * @param name Logger name (as set by logln_config_set_name)
 * @return Logger handle, or NULL if not found
 */
LOGLN_API logln_handle_t logln_get(const char* name);

/**
 * @brief Check if a logger exists
 * @param name Logger name
 * @return true if logger exists
 */
LOGLN_API bool logln_exists(const char* name);

/**
 * @brief Release a logger (flush and cleanup)
 * @param handle Logger handle
 * @return LOGLN_OK on success
 */
LOGLN_API logln_result_t logln_release(logln_handle_t handle);

/**
 * @brief Release a logger by name
 * @param name Logger name
 * @return LOGLN_OK on success, LOGLN_ERROR_NOT_FOUND if not exists
 */
LOGLN_API logln_result_t logln_release_by_name(const char* name);

/**
 * @brief Release all loggers
 */
LOGLN_API void logln_release_all(void);

/**
 * @brief Get logger count
 * @return Number of active loggers
 */
LOGLN_API size_t logln_count(void);

// ============================================================================
// Logging Functions
// ============================================================================

/**
 * @brief Check if a log level is enabled for a logger
 * @param handle Logger handle
 * @param level Log level to check
 * @return true if enabled
 */
LOGLN_API bool logln_is_enabled(logln_handle_t handle, logln_level_t level);

/**
 * @brief Write a log message
 * @param handle Logger handle
 * @param level Log level
 * @param tag Log tag/category
 * @param file Source file name (can be NULL)
 * @param line Source line number
 * @param func Function name (can be NULL)
 * @param fmt printf-style format string
 * @param ... Format arguments
 */
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

/**
 * @brief Write a log message (va_list version)
 */
LOGLN_API void logln_write_v(logln_handle_t handle,
                             logln_level_t level,
                             const char* tag,
                             const char* file,
                             int line,
                             const char* func,
                             const char* fmt,
                             va_list args);

// Convenience macros for logging (require handle)
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
// Logger Control API
// ============================================================================

/**
 * @brief Set log level for a logger
 * @param handle Logger handle
 * @param level New minimum level
 * @return LOGLN_OK on success
 */
LOGLN_API logln_result_t logln_set_level(logln_handle_t handle, logln_level_t level);

/**
 * @brief Get log level for a logger
 * @param handle Logger handle
 * @return Current minimum level
 */
LOGLN_API logln_level_t logln_get_level(logln_handle_t handle);

/**
 * @brief Set write mode for a logger
 * @param handle Logger handle
 * @param mode Write mode
 * @return LOGLN_OK on success
 */
LOGLN_API logln_result_t logln_set_mode(logln_handle_t handle, logln_write_mode_t mode);

/**
 * @brief Enable/disable console output for a logger
 * @param handle Logger handle
 * @param enable true to enable
 * @return LOGLN_OK on success
 */
LOGLN_API logln_result_t logln_set_console_output(logln_handle_t handle, bool enable);

/**
 * @brief Set log format pattern for a logger
 * @param handle Logger handle
 * @param pattern Format pattern
 * @return LOGLN_OK on success
 */
LOGLN_API logln_result_t logln_set_pattern(logln_handle_t handle, const char* pattern);

/**
 * @brief Flush pending logs
 * @param handle Logger handle
 * @return LOGLN_OK on success
 */
LOGLN_API logln_result_t logln_flush(logln_handle_t handle);

/**
 * @brief Flush pending logs synchronously (blocks until complete)
 * @param handle Logger handle
 * @return LOGLN_OK on success
 */
LOGLN_API logln_result_t logln_flush_sync(logln_handle_t handle);

/**
 * @brief Flush all loggers
 * @param sync true for synchronous flush
 * @return LOGLN_OK on success
 */
LOGLN_API logln_result_t logln_flush_all(bool sync);

// ============================================================================
// File Management API
// ============================================================================

/**
 * @brief Get current log file path for a logger
 * @param handle Logger handle
 * @param buffer Output buffer
 * @param buffer_size Buffer size
 * @return Length of path, or -1 on error
 */
LOGLN_API int logln_get_log_path(logln_handle_t handle, char* buffer, size_t buffer_size);

/**
 * @brief Get current cache file path for a logger
 * @param handle Logger handle
 * @param buffer Output buffer
 * @param buffer_size Buffer size
 * @return Length of path, or -1 on error
 */
LOGLN_API int logln_get_cache_path(logln_handle_t handle, char* buffer, size_t buffer_size);

/**
 * @brief Get all log files for a logger
 * @param handle Logger handle
 * @param paths Output array of paths (caller allocates)
 * @param path_buffer_size Size of each path buffer
 * @param max_paths Maximum number of paths to return
 * @param include_current Whether to include the currently active log file
 * @return Number of log files found, or -1 on error
 */
LOGLN_API int logln_get_all_log_files(logln_handle_t handle,
                                       char** paths, 
                                       size_t path_buffer_size,
                                       size_t max_paths,
                                       bool include_current);

/**
 * @brief Remove specific log files
 * @param handle Logger handle
 * @param paths Array of file paths to remove
 * @param count Number of paths
 * @return Number of files successfully removed
 */
LOGLN_API size_t logln_remove_log_files(logln_handle_t handle, 
                                         const char** paths, 
                                         size_t count);

/**
 * @brief Callback for async remove operations
 */
typedef void (*logln_remove_callback_t)(size_t removed_count, void* user_data);

/**
 * @brief Remove log files asynchronously
 * @param handle Logger handle
 * @param paths Array of file paths to remove
 * @param count Number of paths
 * @param callback Optional callback when done
 * @param user_data User context for callback
 */
LOGLN_API void logln_remove_log_files_async(logln_handle_t handle,
                                             const char** paths, 
                                             size_t count,
                                             logln_remove_callback_t callback,
                                             void* user_data);

/**
 * @brief Remove expired log files
 * @param handle Logger handle
 * @param days_ago Remove files older than this many days
 * @return Number of files removed
 */
LOGLN_API size_t logln_remove_expired_log_files(logln_handle_t handle, int days_ago);

/**
 * @brief Remove expired log files asynchronously
 * @param handle Logger handle
 * @param days_ago Remove files older than this many days
 * @param callback Optional callback when done
 * @param user_data User context for callback
 */
LOGLN_API void logln_remove_expired_log_files_async(logln_handle_t handle,
                                                     int days_ago,
                                                     logln_remove_callback_t callback,
                                                     void* user_data);

// ============================================================================
// Utility Functions
// ============================================================================

/**
 * @brief Get version string
 * @return Version string (e.g., "1.0.0")
 */
LOGLN_API const char* logln_version(void);

/**
 * @brief Get version number
 * @return Version as integer (major * 10000 + minor * 100 + patch)
 */
LOGLN_API int logln_version_number(void);

/**
 * @brief Convert level to string
 * @param level Log level
 * @return Level name string
 */
LOGLN_API const char* logln_level_to_string(logln_level_t level);

/**
 * @brief Parse level from string
 * @param str Level string (case-insensitive)
 * @return Log level, or LOGLN_LEVEL_INFO if invalid
 */
LOGLN_API logln_level_t logln_level_from_string(const char* str);

#ifdef __cplusplus
}
#endif

#endif // LOGLN_C_H
