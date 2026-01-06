// SPDX-License-Identifier: MIT
// Copyright (c) 2024 Logln Contributors
//
// Logger - Unified logging API supporting multiple instances
//
// Architecture:
//   Logger (this file)     - User-facing API, formatting, level filtering, multi-instance
//       |
//       v delegates to
//   Appender (internal)    - Low-level I/O, mmap, compression, file management

#include "logln/logger.hpp"
#include "appender.hpp"  // Internal header
#include "utils.hpp"
#include "logln/platform.hpp"

#include <atomic>
#include <mutex>
#include <shared_mutex>
#include <unordered_map>
#include <sstream>
#include <iomanip>
#include <thread>
#include <functional>

namespace logln {

using detail::Appender;  // Use internal Appender

// ============================================================================
// Named Loggers Registry (static)
// ============================================================================

namespace {

struct LoggerRegistry {
    std::shared_mutex mutex;
    std::unordered_map<std::string, std::unique_ptr<Logger>> loggers;
};

LoggerRegistry& get_registry() {
    static LoggerRegistry registry;
    return registry;
}

} // anonymous namespace

// ============================================================================
// Logger Implementation - Thin wrapper around Appender
// ============================================================================

struct Logger::Impl {
    std::string name;  // Empty for anonymous instances
    Config config;
    Formatter formatter;
    std::unique_ptr<Appender> appender;
    
    std::atomic<Level> min_level{Level::Verbose};
    std::atomic<bool> initialized{false};
    std::atomic<bool> closing{false};
    
    // Write callback (set once before logging, no lock needed)
    Logger::WriteCallback write_callback;
    
    explicit Impl(std::string logger_name = "") : name(std::move(logger_name)) {}
    
    void init(const Config& cfg) {
        if (initialized.exchange(true)) {
            return;  // Already initialized
        }
        
        config = cfg;
        min_level.store(cfg.min_level);
        closing.store(false);
        
        // Set custom format pattern if specified
        if (!cfg.format_pattern.empty()) {
            formatter.set_pattern(cfg.format_pattern);
        }
        
        // Create appender - handles all low-level details
        appender = Appender::create(cfg);
    }
    
    void shutdown() {
        if (!initialized.load() || closing.exchange(true)) {
            return;
        }
        
        if (appender) {
            appender->close();
            appender.reset();
        }
        
        initialized.store(false);
    }
};

// ============================================================================
// Static Factory Methods
// ============================================================================

Logger* Logger::instance(const std::string& name) {
    const std::string& lookup_name = name.empty() ? std::string(kDefaultLoggerName) : name;
    
    auto& registry = get_registry();
    std::shared_lock lock(registry.mutex);
    
    auto it = registry.loggers.find(lookup_name);
    return (it != registry.loggers.end()) ? it->second.get() : nullptr;
}

Logger* Logger::create(const Config& config) {
    const std::string& name = config.name_prefix.empty() ? std::string(kDefaultLoggerName) : config.name_prefix;
    
    auto& registry = get_registry();
    std::unique_lock lock(registry.mutex);
    
    // Check if name already exists
    if (registry.loggers.find(name) != registry.loggers.end()) {
        return nullptr;  // Name collision
    }
    
    // Create new logger
    auto logger = std::unique_ptr<Logger>(new Logger(name));
    logger->init(config);
    
    auto* ptr = logger.get();
    registry.loggers[name] = std::move(logger);
    return ptr;
}

Logger* Logger::get(const std::string& name) {
    auto& registry = get_registry();
    std::shared_lock lock(registry.mutex);
    
    auto it = registry.loggers.find(name);
    return (it != registry.loggers.end()) ? it->second.get() : nullptr;
}

bool Logger::exists(const std::string& name) {
    auto& registry = get_registry();
    std::shared_lock lock(registry.mutex);
    return registry.loggers.find(name) != registry.loggers.end();
}

bool Logger::release(const std::string& name) {
    auto& registry = get_registry();
    std::unique_lock lock(registry.mutex);
    
    auto it = registry.loggers.find(name);
    if (it == registry.loggers.end()) {
        return false;
    }
    
    registry.loggers.erase(it);
    return true;
}

void Logger::release_all() {
    auto& registry = get_registry();
    std::unique_lock lock(registry.mutex);
    registry.loggers.clear();
}

std::vector<std::string> Logger::names() {
    auto& registry = get_registry();
    std::shared_lock lock(registry.mutex);
    
    std::vector<std::string> result;
    result.reserve(registry.loggers.size());
    for (const auto& [name, _] : registry.loggers) {
        result.push_back(name);
    }
    return result;
}

std::size_t Logger::count() {
    auto& registry = get_registry();
    std::shared_lock lock(registry.mutex);
    return registry.loggers.size();
}

// ============================================================================
// Constructors / Destructor
// ============================================================================

Logger::Logger() : impl_(std::make_unique<Impl>()) {}

Logger::Logger(std::string name) : impl_(std::make_unique<Impl>(std::move(name))) {}

Logger::~Logger() {
    shutdown();
}

Logger::Logger(Logger&&) noexcept = default;
Logger& Logger::operator=(Logger&&) noexcept = default;

// ============================================================================
// Lifecycle
// ============================================================================

void Logger::init(const Config& config) {
    impl_->init(config);
}

void Logger::shutdown() {
    impl_->shutdown();
}

bool Logger::is_initialized() const noexcept {
    return impl_->initialized.load();
}

const std::string& Logger::name() const noexcept {
    return impl_->name;
}

// ========================================================================
// Configuration - Delegate to Appender
// ========================================================================

const Config& Logger::config() const noexcept {
    return impl_->config;
}

void Logger::set_level(Level level) {
    impl_->min_level.store(level);
}

Level Logger::level() const noexcept {
    return impl_->min_level.load();
}

void Logger::set_console_output(bool enable) {
    if (impl_->appender) {
        impl_->appender->set_console_output(enable);
    }
}

bool Logger::console_output() const noexcept {
    return impl_->appender ? impl_->appender->console_output() : false;
}

void Logger::set_mode(WriteMode mode) {
    if (impl_->appender) {
        impl_->appender->set_mode(mode);
    }
}

WriteMode Logger::mode() const noexcept {
    return impl_->appender ? impl_->appender->mode() : WriteMode::Async;
}

void Logger::set_pattern(std::string_view pattern) {
    impl_->formatter.set_pattern(pattern);
}

void Logger::set_max_file_size(std::uint64_t size) {
    impl_->config.max_file_size = size;
    if (impl_->appender) {
        impl_->appender->set_max_file_size(size);
    }
}

void Logger::set_max_alive_duration(std::chrono::seconds duration) {
    impl_->config.max_alive_duration = duration;
    if (impl_->appender) {
        impl_->appender->set_max_alive_duration(duration);
    }
}

// ============================================================================
// Logging
// ============================================================================

bool Logger::is_enabled(Level level) const noexcept {
    return impl_->initialized.load() && 
           !impl_->closing.load() &&
           level >= impl_->min_level.load();
}

void Logger::log(Level level, 
                 std::string_view tag,
                 std::string_view message,
                 const std::source_location& loc) {
    if (!is_enabled(level)) return;
    if (!impl_->appender) return;
    
    Record record{
        .level = level,
        .tag = tag,
        .message = message,
        .location = loc,
        .timestamp = get_timestamp(),
        .pid = get_pid(),
        .tid = get_tid(),
        .main_tid = get_main_tid()
    };
    
    auto formatted = impl_->formatter.format(record);
    
    // Invoke write callback if set (return false to skip appender)
    if (impl_->write_callback && !impl_->write_callback(record, formatted)) {
        return;
    }
    
    impl_->appender->write(record, std::move(formatted));
}

// ============================================================================
// Flush - Delegate to Appender
// ============================================================================

void Logger::flush() {
    if (impl_->appender) {
        impl_->appender->flush();
    }
}

void Logger::flush_sync() {
    if (impl_->appender) {
        impl_->appender->flush_sync();
    }
}

// ============================================================================
// File Management - Delegate to Appender
// ============================================================================

std::filesystem::path Logger::current_log_path() const {
    std::string path;
    if (impl_->appender && impl_->appender->get_current_log_path(path)) {
        return path;
    }
    return {};
}

std::filesystem::path Logger::current_cache_path() const {
    std::string path;
    if (impl_->appender && impl_->appender->get_current_cache_path(path)) {
        return path;
    }
    return {};
}

std::vector<std::filesystem::path> Logger::get_log_files(int days_ago) const {
    if (impl_->appender) {
        return impl_->appender->get_log_files_from_timespan(days_ago, impl_->config.name_prefix);
    }
    return {};
}

std::vector<std::filesystem::path> Logger::get_all_log_files(bool include_current) const {
    if (impl_->appender) {
        return impl_->appender->get_all_log_files(include_current);
    }
    return {};
}

std::size_t Logger::remove_log_files(const std::vector<std::filesystem::path>& files) {
    if (impl_->appender) {
        return impl_->appender->remove_log_files(files);
    }
    return 0;
}

std::size_t Logger::remove_expired_log_files(int days_ago) {
    if (impl_->appender) {
        return impl_->appender->remove_expired_log_files(days_ago);
    }
    return 0;
}

void Logger::remove_log_files_async(const std::vector<std::filesystem::path>& files,
                                    RemoveCallback callback) {
    if (impl_->appender) {
        impl_->appender->remove_log_files_async(files, std::move(callback));
    }
}

void Logger::remove_expired_log_files_async(int days_ago, RemoveCallback callback) {
    if (impl_->appender) {
        impl_->appender->remove_expired_log_files_async(days_ago, std::move(callback));
    }
}

// ============================================================================
// Callbacks
// ============================================================================

void Logger::set_write_callback(WriteCallback callback) {
    impl_->write_callback = std::move(callback);
}

// ============================================================================
// Debug Utilities
// ============================================================================

std::string Logger::dump(const void* data, std::size_t len) {
    return dump_with_header(data, len);
}

std::string Logger::memory_dump(const void* data, std::size_t len) {
    return hex_dump(data, len);
}

// ============================================================================
// Bulk Operations
// ============================================================================

void Logger::flush_all(bool sync) {
    auto& registry = get_registry();
    std::shared_lock lock(registry.mutex);
    
    for (const auto& [_, logger] : registry.loggers) {
        if (sync) {
            logger->flush_sync();
        } else {
            logger->flush();
        }
    }
}

void Logger::set_level_all(Level level) {
    auto& registry = get_registry();
    std::shared_lock lock(registry.mutex);
    
    for (const auto& [_, logger] : registry.loggers) {
        logger->set_level(level);
    }
}

void Logger::set_mode_all(WriteMode mode) {
    auto& registry = get_registry();
    std::shared_lock lock(registry.mutex);
    
    for (const auto& [_, logger] : registry.loggers) {
        logger->set_mode(mode);
    }
}

} // namespace logln
