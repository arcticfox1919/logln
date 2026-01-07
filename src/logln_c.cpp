// SPDX-License-Identifier: MIT
// Copyright (c) 2024 Logln Contributors

#include "logln/logln_c.h"
#include "logln/logger.hpp"
#include "logln/config.hpp"

#include <cstdarg>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>
#include <thread>
#include <filesystem>

#ifdef _WIN32
#define strcasecmp _stricmp
#endif

// ============================================================================
// Version Info
// ============================================================================

#define LOGLN_VERSION_MAJOR 1
#define LOGLN_VERSION_MINOR 0
#define LOGLN_VERSION_PATCH 0

#define LOGLN_STRINGIFY_(x) #x
#define LOGLN_STRINGIFY(x) LOGLN_STRINGIFY_(x)
#define LOGLN_VERSION_STRING \
    LOGLN_STRINGIFY(LOGLN_VERSION_MAJOR) "." \
    LOGLN_STRINGIFY(LOGLN_VERSION_MINOR) "." \
    LOGLN_STRINGIFY(LOGLN_VERSION_PATCH)

// ============================================================================
// Internal Macros - Guaranteed inlining via macro
// ============================================================================

// Config wrapper for C API
struct ConfigWrapper {
    logln::Config config;
};

// Cast macros - guaranteed to inline, no function call overhead
#define TO_LOGGER(handle)  (reinterpret_cast<logln::Logger*>(handle))
#define TO_HANDLE(logger)  (reinterpret_cast<logln_handle_t>(logger))
#define TO_CONFIG(config)  (static_cast<ConfigWrapper*>(config))

// Null check macros with early return
#define CHECK_HANDLE(handle)        do { if (!(handle)) return LOGLN_ERROR_INVALID; } while(0)
#define CHECK_HANDLE_NULL(handle)   do { if (!(handle)) return nullptr; } while(0)
#define CHECK_HANDLE_VOID(handle)   do { if (!(handle)) return; } while(0)
#define CHECK_HANDLE_BOOL(handle)   do { if (!(handle)) return false; } while(0)
#define CHECK_HANDLE_INT(handle)    do { if (!(handle)) return -1; } while(0)
#define CHECK_HANDLE_ZERO(handle)   do { if (!(handle)) return 0; } while(0)

#define CHECK_CONFIG(config)        CHECK_HANDLE(config)
#define CHECK_CONFIG_NULL(config)   CHECK_HANDLE_NULL(config)

// ============================================================================
// Internal Helpers
// ============================================================================

namespace {

// Convert C level to C++ level
constexpr logln::Level to_cpp_level(logln_level_t level) {
    switch (level) {
        case LOGLN_LEVEL_VERBOSE: return logln::Level::Verbose;
        case LOGLN_LEVEL_DEBUG:   return logln::Level::Debug;
        case LOGLN_LEVEL_INFO:    return logln::Level::Info;
        case LOGLN_LEVEL_WARN:    return logln::Level::Warn;
        case LOGLN_LEVEL_ERROR:   return logln::Level::Error;
        case LOGLN_LEVEL_FATAL:   return logln::Level::Fatal;
        case LOGLN_LEVEL_OFF:     return logln::Level::Off;
        default:                  return logln::Level::Info;
    }
}

// Convert C++ level to C level
constexpr logln_level_t to_c_level(logln::Level level) {
    switch (level) {
        case logln::Level::Verbose: return LOGLN_LEVEL_VERBOSE;
        case logln::Level::Debug:   return LOGLN_LEVEL_DEBUG;
        case logln::Level::Info:    return LOGLN_LEVEL_INFO;
        case logln::Level::Warn:    return LOGLN_LEVEL_WARN;
        case logln::Level::Error:   return LOGLN_LEVEL_ERROR;
        case logln::Level::Fatal:   return LOGLN_LEVEL_FATAL;
        case logln::Level::Off:     return LOGLN_LEVEL_OFF;
        default:                    return LOGLN_LEVEL_INFO;
    }
}

constexpr logln::WriteMode to_cpp_mode(logln_write_mode_t mode) {
    return mode == LOGLN_MODE_SYNC ? logln::WriteMode::Sync : logln::WriteMode::Async;
}

constexpr logln::Compression to_cpp_compression(logln_compression_t comp) {
    return comp == LOGLN_COMPRESS_ZSTD ? logln::Compression::Zstd : logln::Compression::None;
}

// Convert ConfigError to C result code
constexpr logln_result_t config_error_to_result(logln::ConfigError err) {
    switch (err) {
        case logln::ConfigError::EmptyLogDir:           return LOGLN_ERROR_EMPTY_LOG_DIR;
        case logln::ConfigError::EmptyNamePrefix:       return LOGLN_ERROR_EMPTY_NAME_PREFIX;
        case logln::ConfigError::InvalidNamePrefix:     return LOGLN_ERROR_INVALID_NAME_PREFIX;
        case logln::ConfigError::InvalidCompressionLevel: return LOGLN_ERROR_INVALID_COMPRESS_LV;
        case logln::ConfigError::InvalidFlushInterval:  return LOGLN_ERROR_INVALID_FLUSH_INT;
        case logln::ConfigError::InvalidAliveTime:      return LOGLN_ERROR_INVALID_ALIVE_TIME;
        case logln::ConfigError::InvalidCacheDays:      return LOGLN_ERROR_INVALID_CACHE_DAYS;
        case logln::ConfigError::LogDirNotWritable:     return LOGLN_ERROR_LOG_DIR_NOT_WRITABLE;
        case logln::ConfigError::CacheDirNotWritable:   return LOGLN_ERROR_CACHE_DIR_NOT_WRITABLE;
        default:                                        return LOGLN_ERROR_INVALID;
    }
}

// Thread-safe printf-style formatting
std::string format_message(const char* fmt, va_list args) {
    va_list args_copy;
    va_copy(args_copy, args);
    
    int len = std::vsnprintf(nullptr, 0, fmt, args_copy);
    va_end(args_copy);
    
    if (len < 0) return {};
    
    std::vector<char> buffer(static_cast<size_t>(len) + 1);
    std::vsnprintf(buffer.data(), buffer.size(), fmt, args);
    
    return std::string(buffer.data(), static_cast<size_t>(len));
}

// Apply options structure to Config
void apply_options_to_config(logln::Config& cfg, const logln_config_options_t* opts) {
    if (opts->log_dir)   cfg.log_dir = opts->log_dir;
    if (opts->cache_dir) cfg.cache_dir = opts->cache_dir;
    if (opts->name)      cfg.name_prefix = opts->name;
    if (opts->format)    cfg.format_pattern = opts->format;
    
    cfg.min_level = to_cpp_level(opts->min_level);
    cfg.mode = to_cpp_mode(opts->mode);
    cfg.compression = to_cpp_compression(opts->compression);
    
    if (opts->compression_level > 0) {
        cfg.compression_level = opts->compression_level;
    }
    if (opts->max_file_size > 0) {
        cfg.max_file_size = opts->max_file_size;
    }
    if (opts->max_alive_seconds > 0) {
        cfg.max_alive_duration = std::chrono::seconds{opts->max_alive_seconds};
    }
    if (opts->flush_interval_ms > 0) {
        cfg.flush_interval = std::chrono::milliseconds{opts->flush_interval_ms};
    }
    if (opts->cache_days >= 0) {
        cfg.cache_days = opts->cache_days;
    }
    
    if (opts->pub_key && *opts->pub_key) {
        cfg.pub_key = std::string(opts->pub_key);
    }
    
    cfg.console_output = opts->console_output;
}

} // anonymous namespace

// ============================================================================
// Configuration API
// ============================================================================

extern "C" {

logln_config_t logln_config_create(void) {
    try {
        return static_cast<logln_config_t>(new ConfigWrapper{});
    } catch (...) {
        return nullptr;
    }
}

void logln_config_destroy(logln_config_t config) {
    delete TO_CONFIG(config);
}

logln_result_t logln_config_set_log_dir(logln_config_t config, const char* path) {
    CHECK_CONFIG(config);
    if (!path) return LOGLN_ERROR_INVALID;
    TO_CONFIG(config)->config.log_dir = path;
    return LOGLN_OK;
}

logln_result_t logln_config_set_cache_dir(logln_config_t config, const char* path) {
    CHECK_CONFIG(config);
    if (!path) return LOGLN_ERROR_INVALID;
    TO_CONFIG(config)->config.cache_dir = path;
    return LOGLN_OK;
}

logln_result_t logln_config_set_name(logln_config_t config, const char* name) {
    CHECK_CONFIG(config);
    if (!name) return LOGLN_ERROR_INVALID;
    TO_CONFIG(config)->config.name_prefix = name;
    return LOGLN_OK;
}

logln_result_t logln_config_set_mode(logln_config_t config, logln_write_mode_t mode) {
    CHECK_CONFIG(config);
    TO_CONFIG(config)->config.mode = to_cpp_mode(mode);
    return LOGLN_OK;
}

logln_result_t logln_config_set_compression(logln_config_t config, 
                                             logln_compression_t compression,
                                             int level) {
    CHECK_CONFIG(config);
    auto* wrapper = TO_CONFIG(config);
    wrapper->config.compression = to_cpp_compression(compression);
    wrapper->config.compression_level = level;
    return LOGLN_OK;
}

logln_result_t logln_config_set_pub_key(logln_config_t config, const char* pub_key) {
    CHECK_CONFIG(config);
    if (pub_key && *pub_key) {
        TO_CONFIG(config)->config.pub_key = std::string(pub_key);
    } else {
        TO_CONFIG(config)->config.pub_key.reset();
    }
    return LOGLN_OK;
}

logln_result_t logln_config_set_max_file_size(logln_config_t config, uint64_t max_bytes) {
    CHECK_CONFIG(config);
    TO_CONFIG(config)->config.max_file_size = max_bytes;
    return LOGLN_OK;
}

logln_result_t logln_config_set_max_alive_duration(logln_config_t config, int64_t seconds) {
    CHECK_CONFIG(config);
    TO_CONFIG(config)->config.max_alive_duration = std::chrono::seconds{seconds};
    return LOGLN_OK;
}

logln_result_t logln_config_set_console_output(logln_config_t config, bool enable) {
    CHECK_CONFIG(config);
    TO_CONFIG(config)->config.console_output = enable;
    return LOGLN_OK;
}

logln_result_t logln_config_set_min_level(logln_config_t config, logln_level_t level) {
    CHECK_CONFIG(config);
    TO_CONFIG(config)->config.min_level = to_cpp_level(level);
    return LOGLN_OK;
}

logln_result_t logln_config_set_format(logln_config_t config, const char* format) {
    CHECK_CONFIG(config);
    if (!format) return LOGLN_ERROR_INVALID;
    TO_CONFIG(config)->config.format_pattern = format;
    return LOGLN_OK;
}

logln_result_t logln_config_validate(logln_config_t config) {
    CHECK_CONFIG(config);
    
    auto result = TO_CONFIG(config)->config.validate();
    if (result) return LOGLN_OK;
    
    const auto& errors = result.error();
    return errors.empty() ? LOGLN_ERROR_INVALID : config_error_to_result(errors[0]);
}

int logln_config_validate_all(logln_config_t config, 
                               logln_result_t* errors, 
                               int max_errors) {
    if (!config) return 0;
    
    auto result = TO_CONFIG(config)->config.validate();
    if (result) return 0;
    
    const auto& error_list = result.error();
    int count = static_cast<int>(error_list.size());
    
    if (errors && max_errors > 0) {
        int to_copy = std::min(count, max_errors);
        for (int i = 0; i < to_copy; ++i) {
            errors[i] = config_error_to_result(error_list[i]);
        }
    }
    
    return count;
}

const char* logln_result_message(logln_result_t result) {
    switch (result) {
        case LOGLN_OK:                          return "Success";
        case LOGLN_ERROR_INVALID:               return "Invalid parameter";
        case LOGLN_ERROR_NOT_INIT:              return "Logger not initialized";
        case LOGLN_ERROR_ALREADY:               return "Already exists (name collision)";
        case LOGLN_ERROR_NOT_FOUND:             return "Logger not found";
        case LOGLN_ERROR_IO:                    return "I/O error";
        case LOGLN_ERROR_MEMORY:                return "Memory allocation failed";
        case LOGLN_ERROR_EMPTY_LOG_DIR:         return "log_dir cannot be empty";
        case LOGLN_ERROR_EMPTY_NAME_PREFIX:     return "name cannot be empty";
        case LOGLN_ERROR_INVALID_NAME_PREFIX:   return "name contains invalid characters";
        case LOGLN_ERROR_INVALID_COMPRESS_LV:   return "compression_level must be in range [1, 22]";
        case LOGLN_ERROR_INVALID_FLUSH_INT:     return "flush_interval must be at least 100ms";
        case LOGLN_ERROR_INVALID_ALIVE_TIME:    return "max_alive_duration must be at least 24 hours";
        case LOGLN_ERROR_INVALID_CACHE_DAYS:    return "cache_days cannot be negative";
        case LOGLN_ERROR_LOG_DIR_NOT_WRITABLE:  return "log_dir is not writable";
        case LOGLN_ERROR_CACHE_DIR_NOT_WRITABLE:return "cache_dir is not writable";
        default:                                return "Unknown error";
    }
}

// ============================================================================
// Logger Lifecycle API
// ============================================================================

logln_handle_t logln_create(logln_config_t config) {
    CHECK_CONFIG_NULL(config);
    
    try {
        return TO_HANDLE(logln::Logger::create(TO_CONFIG(config)->config));
    } catch (...) {
        return nullptr;
    }
}

logln_handle_t logln_create_with_options(const logln_config_options_t* options) {
    if (!options) return nullptr;
    
    try {
        logln::Config cfg;
        apply_options_to_config(cfg, options);
        return TO_HANDLE(logln::Logger::create(cfg));
    } catch (...) {
        return nullptr;
    }
}

logln_result_t logln_validate_options(const logln_config_options_t* options) {
    if (!options) return LOGLN_ERROR_INVALID;
    
    logln::Config cfg;
    apply_options_to_config(cfg, options);
    
    auto result = cfg.validate();
    if (result) return LOGLN_OK;
    
    const auto& errors = result.error();
    return errors.empty() ? LOGLN_ERROR_INVALID : config_error_to_result(errors[0]);
}

logln_result_t logln_create_async(logln_config_t config,
                                   logln_create_callback_t callback,
                                   void* user_data) {
    CHECK_CONFIG(config);
    
    // Copy config for thread safety
    auto cfg = TO_CONFIG(config)->config;
    
    std::thread([cfg, callback, user_data]() {
        auto* logger = logln::Logger::create(cfg);
        if (callback) {
            callback(TO_HANDLE(logger), logger != nullptr, user_data);
        }
    }).detach();
    
    return LOGLN_OK;
}

logln_handle_t logln_get(const char* name) {
    if (!name) return nullptr;
    return TO_HANDLE(logln::Logger::get(name));
}

bool logln_exists(const char* name) {
    if (!name) return false;
    return logln::Logger::exists(name);
}

logln_result_t logln_release(logln_handle_t handle) {
    CHECK_HANDLE(handle);
    return logln::Logger::release(TO_LOGGER(handle)->name()) ? LOGLN_OK : LOGLN_ERROR_NOT_FOUND;
}

logln_result_t logln_release_by_name(const char* name) {
    if (!name) return LOGLN_ERROR_INVALID;
    return logln::Logger::release(name) ? LOGLN_OK : LOGLN_ERROR_NOT_FOUND;
}

void logln_release_all(void) {
    logln::Logger::release_all();
}

size_t logln_count(void) {
    return logln::Logger::count();
}

// ============================================================================
// Logging Functions
// ============================================================================

bool logln_is_enabled(logln_handle_t handle, logln_level_t level) {
    CHECK_HANDLE_BOOL(handle);
    return TO_LOGGER(handle)->is_enabled(to_cpp_level(level));
}

void logln_write(logln_handle_t handle,
                 logln_level_t level,
                 const char* tag,
                 [[maybe_unused]] const char* file,
                 [[maybe_unused]] int line,
                 [[maybe_unused]] const char* func,
                 const char* fmt, ...) {
    CHECK_HANDLE_VOID(handle);
    
    auto* logger = TO_LOGGER(handle);
    auto cpp_level = to_cpp_level(level);
    if (!logger->is_enabled(cpp_level)) return;
    
    va_list args;
    va_start(args, fmt);
    std::string message = format_message(fmt, args);
    va_end(args);
    
    logger->log(cpp_level, tag ? tag : "", message);
}

void logln_write_v(logln_handle_t handle,
                   logln_level_t level,
                   const char* tag,
                   [[maybe_unused]] const char* file,
                   [[maybe_unused]] int line,
                   [[maybe_unused]] const char* func,
                   const char* fmt,
                   va_list args) {
    CHECK_HANDLE_VOID(handle);
    
    auto* logger = TO_LOGGER(handle);
    auto cpp_level = to_cpp_level(level);
    if (!logger->is_enabled(cpp_level)) return;
    
    std::string message = format_message(fmt, args);
    logger->log(cpp_level, tag ? tag : "", message);
}

// ============================================================================
// Logger Control API
// ============================================================================

logln_result_t logln_set_level(logln_handle_t handle, logln_level_t level) {
    CHECK_HANDLE(handle);
    TO_LOGGER(handle)->set_level(to_cpp_level(level));
    return LOGLN_OK;
}

logln_level_t logln_get_level(logln_handle_t handle) {
    if (!handle) return LOGLN_LEVEL_INFO;
    return to_c_level(TO_LOGGER(handle)->level());
}

logln_result_t logln_set_mode(logln_handle_t handle, logln_write_mode_t mode) {
    CHECK_HANDLE(handle);
    TO_LOGGER(handle)->set_mode(to_cpp_mode(mode));
    return LOGLN_OK;
}

logln_result_t logln_set_console_output(logln_handle_t handle, bool enable) {
    CHECK_HANDLE(handle);
    TO_LOGGER(handle)->set_console_output(enable);
    return LOGLN_OK;
}

logln_result_t logln_set_pattern(logln_handle_t handle, const char* pattern) {
    CHECK_HANDLE(handle);
    if (!pattern) return LOGLN_ERROR_INVALID;
    TO_LOGGER(handle)->set_pattern(pattern);
    return LOGLN_OK;
}

logln_result_t logln_flush(logln_handle_t handle) {
    CHECK_HANDLE(handle);
    TO_LOGGER(handle)->flush();
    return LOGLN_OK;
}

logln_result_t logln_flush_sync(logln_handle_t handle) {
    CHECK_HANDLE(handle);
    TO_LOGGER(handle)->flush_sync();
    return LOGLN_OK;
}

logln_result_t logln_flush_all(bool sync) {
    logln::Logger::flush_all(sync);
    return LOGLN_OK;
}

// ============================================================================
// File Management API
// ============================================================================

int logln_get_log_path(logln_handle_t handle, char* buffer, size_t buffer_size) {
    CHECK_HANDLE_INT(handle);
    if (!buffer || buffer_size == 0) return -1;
    
    auto path = TO_LOGGER(handle)->current_log_path();
    auto str = path.string();
    
    if (str.size() >= buffer_size) return -1;
    
    std::strcpy(buffer, str.c_str());
    return static_cast<int>(str.size());
}

int logln_get_cache_path(logln_handle_t handle, char* buffer, size_t buffer_size) {
    CHECK_HANDLE_INT(handle);
    if (!buffer || buffer_size == 0) return -1;
    
    auto path = TO_LOGGER(handle)->current_cache_path();
    auto str = path.string();
    
    if (str.size() >= buffer_size) return -1;
    
    std::strcpy(buffer, str.c_str());
    return static_cast<int>(str.size());
}

int logln_get_all_log_files(logln_handle_t handle,
                             char** paths, 
                             size_t path_buffer_size,
                             size_t max_paths,
                             bool include_current) {
    CHECK_HANDLE_INT(handle);
    if (!paths || path_buffer_size == 0 || max_paths == 0) return -1;
    
    auto files = TO_LOGGER(handle)->get_all_log_files(include_current);
    
    size_t count = std::min(files.size(), max_paths);
    for (size_t i = 0; i < count; ++i) {
        auto str = files[i].string();
        if (str.size() < path_buffer_size) {
            std::strcpy(paths[i], str.c_str());
        }
    }
    
    return static_cast<int>(count);
}

size_t logln_remove_log_files(logln_handle_t handle, 
                               const char** paths, 
                               size_t count) {
    CHECK_HANDLE_ZERO(handle);
    if (!paths || count == 0) return 0;
    
    std::vector<std::filesystem::path> file_paths;
    file_paths.reserve(count);
    
    for (size_t i = 0; i < count; ++i) {
        if (paths[i]) {
            file_paths.emplace_back(paths[i]);
        }
    }
    
    return TO_LOGGER(handle)->remove_log_files(file_paths);
}

void logln_remove_log_files_async(logln_handle_t handle,
                                   const char** paths, 
                                   size_t count,
                                   logln_remove_callback_t callback,
                                   void* user_data) {
    if (!handle || !paths || count == 0) {
        if (callback) callback(0, user_data);
        return;
    }
    
    // Copy paths for thread safety
    std::vector<std::filesystem::path> file_paths;
    file_paths.reserve(count);
    
    for (size_t i = 0; i < count; ++i) {
        if (paths[i]) {
            file_paths.emplace_back(paths[i]);
        }
    }
    
    TO_LOGGER(handle)->remove_log_files_async(
        file_paths, 
        [callback, user_data](std::size_t removed) {
            if (callback) callback(removed, user_data);
        });
}

size_t logln_remove_expired_log_files(logln_handle_t handle, int days_ago) {
    CHECK_HANDLE_ZERO(handle);
    return TO_LOGGER(handle)->remove_expired_log_files(days_ago);
}

void logln_remove_expired_log_files_async(logln_handle_t handle,
                                           int days_ago,
                                           logln_remove_callback_t callback,
                                           void* user_data) {
    if (!handle) {
        if (callback) callback(0, user_data);
        return;
    }
    
    TO_LOGGER(handle)->remove_expired_log_files_async(
        days_ago,
        [callback, user_data](std::size_t removed) {
            if (callback) callback(removed, user_data);
        });
}

// ============================================================================
// Utility Functions
// ============================================================================

const char* logln_version(void) {
    return LOGLN_VERSION_STRING;
}

int logln_version_number(void) {
    return LOGLN_VERSION_MAJOR * 10000 + LOGLN_VERSION_MINOR * 100 + LOGLN_VERSION_PATCH;
}

const char* logln_level_to_string(logln_level_t level) {
    switch (level) {
        case LOGLN_LEVEL_VERBOSE: return "VERBOSE";
        case LOGLN_LEVEL_DEBUG:   return "DEBUG";
        case LOGLN_LEVEL_INFO:    return "INFO";
        case LOGLN_LEVEL_WARN:    return "WARN";
        case LOGLN_LEVEL_ERROR:   return "ERROR";
        case LOGLN_LEVEL_FATAL:   return "FATAL";
        case LOGLN_LEVEL_OFF:     return "OFF";
        default:                  return "UNKNOWN";
    }
}

logln_level_t logln_level_from_string(const char* str) {
    if (!str) return LOGLN_LEVEL_INFO;
    
    if (strcasecmp(str, "verbose") == 0 || strcasecmp(str, "v") == 0) return LOGLN_LEVEL_VERBOSE;
    if (strcasecmp(str, "debug") == 0 || strcasecmp(str, "d") == 0)   return LOGLN_LEVEL_DEBUG;
    if (strcasecmp(str, "info") == 0 || strcasecmp(str, "i") == 0)    return LOGLN_LEVEL_INFO;
    if (strcasecmp(str, "warn") == 0 || strcasecmp(str, "w") == 0)    return LOGLN_LEVEL_WARN;
    if (strcasecmp(str, "warning") == 0)                               return LOGLN_LEVEL_WARN;
    if (strcasecmp(str, "error") == 0 || strcasecmp(str, "e") == 0)   return LOGLN_LEVEL_ERROR;
    if (strcasecmp(str, "fatal") == 0 || strcasecmp(str, "f") == 0)   return LOGLN_LEVEL_FATAL;
    if (strcasecmp(str, "off") == 0 || strcasecmp(str, "none") == 0)  return LOGLN_LEVEL_OFF;
    
    return LOGLN_LEVEL_INFO;
}

} // extern "C"
