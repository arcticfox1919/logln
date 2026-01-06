// SPDX-License-Identifier: MIT
// Copyright (c) 2024 Logln Contributors

#pragma once

#include "types.hpp"
#include "config.hpp"
#include "formatter.hpp"

#include <string>
#include <string_view>
#include <format>
#include <source_location>
#include <memory>
#include <vector>
#include <functional>
#include <future>

namespace logln {

// ============================================================================
// Logger - Unified Logging API (supports multiple instances)
// ============================================================================

class Logger {
public:
    // ========================================================================
    // Static Factory Methods
    // ========================================================================
    
    /**
     * @brief Get logger by name, or the default logger if name is empty
     * @param name Logger name to lookup. This must match the config.name_prefix 
     *             used when calling create(). If empty, returns the default logger
     *             (created with name_prefix = kDefaultLoggerName = "Logln").
     * @return Pointer to the logger, nullptr if not found
     * 
     * @note The name parameter corresponds to config.name_prefix, NOT the log file name.
     *       For example:
     *         Config cfg;
     *         cfg.name_prefix = "Network";  // This is the lookup key
     *         Logger::create(cfg);
     *         Logger::instance("Network");  // Use same name to retrieve
     * 
     * Usage:
     *   Logger::instance()           // Get default logger (name_prefix = "Logln")
     *   Logger::instance("Network")  // Get logger created with name_prefix = "Network"
     */
    [[nodiscard]] static Logger* instance(const std::string& name = "");
    
    /**
     * @brief Create and register a logger using config.name_prefix as name
     * @param config Configuration (name_prefix is used as registration name)
     * @return Pointer to created logger, nullptr if name already exists
     * 
     * The logger is registered with config.name_prefix as its name.
     * If config.name_prefix is empty or "Logln", creates the default logger.
     * 
     * @warning This performs I/O operations (directory creation, mmap file setup)
     *          and may block. On mobile platforms, consider calling from a 
     *          background thread.
     */
    static Logger* create(const Config& config);
    
    /**
     * @brief Get a named logger by name
     */
    [[nodiscard]] static Logger* get(const std::string& name);
    
    /**
     * @brief Check if a named logger exists
     */
    [[nodiscard]] static bool exists(const std::string& name);
    
    /**
     * @brief Release a named logger
     */
    static bool release(const std::string& name);
    
    /**
     * @brief Release all named loggers
     */
    static void release_all();
    
    /**
     * @brief Get all registered logger names
     */
    [[nodiscard]] static std::vector<std::string> names();
    
    /**
     * @brief Get count of named loggers
     */
    [[nodiscard]] static std::size_t count();
    
    // ========================================================================
    // Lifecycle
    // ========================================================================
    
    ~Logger();
    
    // Move-only
    Logger(Logger&&) noexcept;
    Logger& operator=(Logger&&) noexcept;
    
    // Non-copyable
    Logger(const Logger&) = delete;
    Logger& operator=(const Logger&) = delete;
    
    /**
     * @brief Shutdown and flush all pending logs
     */
    void shutdown();
    
    /**
     * @brief Check if logger is initialized
     */
    [[nodiscard]] bool is_initialized() const noexcept;
    
    /**
     * @brief Get the logger's name (empty for anonymous instances)
     */
    [[nodiscard]] const std::string& name() const noexcept;
    
    // ========================================================================
    // Configuration
    // ========================================================================
    
    [[nodiscard]] const Config& config() const noexcept;
    
    void set_level(Level level);
    [[nodiscard]] Level level() const noexcept;
    
    void set_console_output(bool enable);
    [[nodiscard]] bool console_output() const noexcept;
    
    void set_mode(WriteMode mode);
    [[nodiscard]] WriteMode mode() const noexcept;
    
    void set_pattern(std::string_view pattern);
    
    void set_max_file_size(std::uint64_t size);
    void set_max_alive_duration(std::chrono::seconds duration);
    
    // ========================================================================
    // Logging
    // ========================================================================
    
    [[nodiscard]] bool is_enabled(Level level) const noexcept;
    
    void log(Level level, 
             std::string_view tag,
             std::string_view message,
             const std::source_location& loc = std::source_location::current());
    
    template<typename... Args>
    void log(Level level,
             std::string_view tag,
             std::format_string<Args...> fmt,
             Args&&... args) {
        if (!is_enabled(level)) return;
        log(level, tag, std::format(fmt, std::forward<Args>(args)...));
    }
    
    // Convenience methods
    template<typename... Args>
    void verbose(std::string_view tag, std::format_string<Args...> fmt, Args&&... args) {
        log(Level::Verbose, tag, fmt, std::forward<Args>(args)...);
    }
    
    template<typename... Args>
    void debug(std::string_view tag, std::format_string<Args...> fmt, Args&&... args) {
        log(Level::Debug, tag, fmt, std::forward<Args>(args)...);
    }
    
    template<typename... Args>
    void info(std::string_view tag, std::format_string<Args...> fmt, Args&&... args) {
        log(Level::Info, tag, fmt, std::forward<Args>(args)...);
    }
    
    template<typename... Args>
    void warn(std::string_view tag, std::format_string<Args...> fmt, Args&&... args) {
        log(Level::Warn, tag, fmt, std::forward<Args>(args)...);
    }
    
    template<typename... Args>
    void error(std::string_view tag, std::format_string<Args...> fmt, Args&&... args) {
        log(Level::Error, tag, fmt, std::forward<Args>(args)...);
    }
    
    template<typename... Args>
    void fatal(std::string_view tag, std::format_string<Args...> fmt, Args&&... args) {
        log(Level::Fatal, tag, fmt, std::forward<Args>(args)...);
    }
    
    // ========================================================================
    // Flush
    // ========================================================================
    
    void flush();
    void flush_sync();
    
    // ========================================================================
    // File Management
    // ========================================================================
    
    [[nodiscard]] std::filesystem::path current_log_path() const;
    [[nodiscard]] std::filesystem::path current_cache_path() const;
    [[nodiscard]] std::vector<std::filesystem::path> get_log_files(int days_ago = 0) const;
    [[nodiscard]] std::vector<std::filesystem::path> get_all_log_files(bool include_current = false) const;
    
    std::size_t remove_log_files(const std::vector<std::filesystem::path>& files);
    std::size_t remove_expired_log_files(int days_ago);
    
    using RemoveCallback = std::function<void(std::size_t removed_count)>;
    void remove_log_files_async(const std::vector<std::filesystem::path>& files,
                                RemoveCallback callback = nullptr);
    void remove_expired_log_files_async(int days_ago, RemoveCallback callback = nullptr);
    
    // ========================================================================
    // Callbacks
    // ========================================================================
    
    // Return true to continue writing, false to skip appender
    using WriteCallback = std::function<bool(const Record&, std::string_view formatted)>;
    void set_write_callback(WriteCallback callback);
    
    // ========================================================================
    // Debug Utilities
    // ========================================================================
    
    [[nodiscard]] static std::string dump(const void* data, std::size_t len);
    [[nodiscard]] static std::string memory_dump(const void* data, std::size_t len);
    
    // ========================================================================
    // Bulk Operations (for all named loggers)
    // ========================================================================
    
    static void flush_all(bool sync = false);
    static void set_level_all(Level level);
    static void set_mode_all(WriteMode mode);

private:
    Logger();
    explicit Logger(std::string name);
    
    /**
     * @brief Initialize the logger with configuration (called by create())
     */
    void init(const Config& config);
    
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

// ============================================================================
// Convenience Macros
// ============================================================================

// These macros use the default logger. Make sure to call Logger::create() first.
// If the logger doesn't exist, these will crash (null pointer dereference).

#define LOGLN_V(tag, ...) \
    do { if (auto* _l = ::logln::Logger::instance()) _l->verbose(tag, __VA_ARGS__); } while(0)

#define LOGLN_D(tag, ...) \
    do { if (auto* _l = ::logln::Logger::instance()) _l->debug(tag, __VA_ARGS__); } while(0)

#define LOGLN_I(tag, ...) \
    do { if (auto* _l = ::logln::Logger::instance()) _l->info(tag, __VA_ARGS__); } while(0)

#define LOGLN_W(tag, ...) \
    do { if (auto* _l = ::logln::Logger::instance()) _l->warn(tag, __VA_ARGS__); } while(0)

#define LOGLN_E(tag, ...) \
    do { if (auto* _l = ::logln::Logger::instance()) _l->error(tag, __VA_ARGS__); } while(0)

#define LOGLN_F(tag, ...) \
    do { if (auto* _l = ::logln::Logger::instance()) _l->fatal(tag, __VA_ARGS__); } while(0)

// With automatic tag from function name
#define LOG_V(...) LOGLN_V(__func__, __VA_ARGS__)
#define LOG_D(...) LOGLN_D(__func__, __VA_ARGS__)
#define LOG_I(...) LOGLN_I(__func__, __VA_ARGS__)
#define LOG_W(...) LOGLN_W(__func__, __VA_ARGS__)
#define LOG_E(...) LOGLN_E(__func__, __VA_ARGS__)
#define LOG_F(...) LOGLN_F(__func__, __VA_ARGS__)

// ============================================================================
// Convenience Functions (backward compatibility)
// ============================================================================

/**
 * @brief Create a logger using config.name_prefix as name
 */
inline Logger* create_logger(const Config& config) {
    return Logger::create(config);
}

/**
 * @brief Get an existing named logger
 */
inline Logger* get_logger(const std::string& name) {
    return Logger::get(name);
}

/**
 * @brief Release a named logger
 */
inline bool release_logger(const std::string& name) {
    return Logger::release(name);
}

} // namespace logln
