// SPDX-License-Identifier: MIT
// Copyright (c) 2024 Logln Contributors

#pragma once

#include "types.hpp"

#include <string>
#include <string_view>
#include <filesystem>
#include <chrono>
#include <optional>
#include <expected>
#include <cstdint>
#include <vector>

namespace logln {

// ============================================================================
// Constants
// ============================================================================

/// Default logger name used when no name_prefix is specified
inline constexpr const char* kDefaultLoggerName = "Logln";

/// Constraints
inline constexpr int kMinCompressionLevel = 1;
inline constexpr int kMaxCompressionLevel = 22;
inline constexpr auto kMinFlushInterval = std::chrono::milliseconds{100};
inline constexpr auto kMinAliveTime = std::chrono::hours{24};  // 1 day minimum

// ============================================================================
// Configuration Error
// ============================================================================

enum class ConfigError {
    EmptyLogDir,
    EmptyNamePrefix,
    InvalidNamePrefix,         // Contains invalid characters
    InvalidCompressionLevel,   // Out of range [1, 22]
    InvalidFlushInterval,      // Too short
    InvalidAliveTime,          // Too short
    InvalidCacheDays,          // Negative
    LogDirNotWritable,         // Cannot create/write to log_dir
    CacheDirNotWritable,       // Cannot create/write to cache_dir
};

/// Get human-readable error message
[[nodiscard]] constexpr std::string_view config_error_message(ConfigError err) noexcept {
    switch (err) {
        case ConfigError::EmptyLogDir:
            return "log_dir cannot be empty";
        case ConfigError::EmptyNamePrefix:
            return "name_prefix cannot be empty";
        case ConfigError::InvalidNamePrefix:
            return "name_prefix contains invalid characters (only alphanumeric, underscore, hyphen allowed)";
        case ConfigError::InvalidCompressionLevel:
            return "compression_level must be in range [1, 22]";
        case ConfigError::InvalidFlushInterval:
            return "flush_interval must be at least 100ms";
        case ConfigError::InvalidAliveTime:
            return "max_alive_duration must be at least 24 hours";
        case ConfigError::InvalidCacheDays:
            return "cache_days cannot be negative";
        case ConfigError::LogDirNotWritable:
            return "log_dir is not writable or cannot be created";
        case ConfigError::CacheDirNotWritable:
            return "cache_dir is not writable or cannot be created";
    }
    return "unknown configuration error";
}

// ============================================================================
// Configuration
// ============================================================================

struct Config {
    // Required: Log output directory
    std::filesystem::path log_dir;
    
    // Optional: Cache directory (for low storage scenarios)
    std::filesystem::path cache_dir;
    
    // Logger name and file prefix (e.g., "myapp" -> "myapp_20241127.log")
    // This is also used as the logger's registration name
    std::string name_prefix = kDefaultLoggerName;
    
    // Log format pattern (empty = use default)
    // Supported tokens: {level}, {Level}, {time}, {time6}, {date}, {pid}, {tid}, 
    //                   {tid*}, {tag}, {file}, {path}, {line}, {func}, {msg}, {n}
    std::string format_pattern;
    
    // Write mode: Async (default) or Sync
    WriteMode mode = WriteMode::Async;
    
    // Compression settings
    Compression compression = Compression::None;
    
    /// Zstd compression level (1-22).
    /// Level 3 is optimal for logs: 84% compression at 89K ops/s.
    /// Higher levels (e.g., 22) are 84x slower with no compression gain.
    int compression_level = 3;
    
    // Encryption public key (secp256k1 ECDH + ChaCha20)
    // If empty, encryption is disabled
    std::optional<std::string> pub_key;
    
    // Log retention
    std::chrono::seconds max_alive_duration = std::chrono::hours{24 * 10};  // 10 days
    
    // Async flush interval (default: 15 minutes)
    std::chrono::milliseconds flush_interval = std::chrono::minutes{15};
    
    // File size limit (0 = no limit, single file per day)
    std::uint64_t max_file_size = 0;
    
    // Cache settings
    int cache_days = 0;  // Days to keep logs in cache before moving to log_dir
    
    // Console output
    bool console_output = 
#ifdef NDEBUG
        false;
#else
        true;
#endif
    
    // Minimum log level
    Level min_level = Level::Verbose;
    
    // ========================================================================
    // Validation
    // ========================================================================
    
    /// Quick check (for backward compatibility)
    [[nodiscard]] bool is_valid() const noexcept {
        return !log_dir.empty() && !name_prefix.empty();
    }
    
    /// Comprehensive validation returning all errors
    [[nodiscard]] std::expected<void, std::vector<ConfigError>> validate() const {
        std::vector<ConfigError> errors;
        
        // Required fields
        if (log_dir.empty()) {
            errors.push_back(ConfigError::EmptyLogDir);
        }
        
        if (name_prefix.empty()) {
            errors.push_back(ConfigError::EmptyNamePrefix);
        } else if (!is_valid_name_prefix(name_prefix)) {
            errors.push_back(ConfigError::InvalidNamePrefix);
        }
        
        // Range checks
        if (compression != Compression::None && 
            (compression_level < kMinCompressionLevel || compression_level > kMaxCompressionLevel)) {
            errors.push_back(ConfigError::InvalidCompressionLevel);
        }
        
        if (flush_interval < kMinFlushInterval) {
            errors.push_back(ConfigError::InvalidFlushInterval);
        }
        
        if (max_alive_duration < kMinAliveTime) {
            errors.push_back(ConfigError::InvalidAliveTime);
        }
        
        if (cache_days < 0) {
            errors.push_back(ConfigError::InvalidCacheDays);
        }
        
        if (errors.empty()) {
            return {};
        }
        return std::unexpected(std::move(errors));
    }
    
    /// Validate with directory writability check (may create directories)
    /// @warning This performs I/O operations and may block. On mobile platforms,
    ///          consider calling on a background thread.
    [[nodiscard]] std::expected<void, std::vector<ConfigError>> validate_with_dirs() const {
        auto result = validate();
        std::vector<ConfigError> errors;
        
        if (!result) {
            errors = std::move(result.error());
        }
        
        // Check directory writability
        if (!log_dir.empty()) {
            std::error_code ec;
            std::filesystem::create_directories(log_dir, ec);
            if (ec) {
                errors.push_back(ConfigError::LogDirNotWritable);
            }
        }
        
        if (!cache_dir.empty()) {
            std::error_code ec;
            std::filesystem::create_directories(cache_dir, ec);
            if (ec) {
                errors.push_back(ConfigError::CacheDirNotWritable);
            }
        }
        
        if (errors.empty()) {
            return {};
        }
        return std::unexpected(std::move(errors));
    }
    
private:
    [[nodiscard]] static bool is_valid_name_prefix(std::string_view name) noexcept {
        if (name.empty()) return false;
        
        for (char c : name) {
            // Allow alphanumeric, underscore, hyphen
            if (!std::isalnum(static_cast<unsigned char>(c)) && c != '_' && c != '-') {
                return false;
            }
        }
        return true;
    }
};

// ============================================================================
// Config Builder (Fluent API with optional semantics)
// ============================================================================

class ConfigBuilder {
public:
    ConfigBuilder() = default;
    
    /// Set required log directory
    ConfigBuilder& log_dir(std::filesystem::path path) {
        config_.log_dir = std::move(path);
        return *this;
    }
    
    /// Set optional cache directory
    ConfigBuilder& cache_dir(std::filesystem::path path) {
        config_.cache_dir = std::move(path);
        return *this;
    }
    
    /// Set logger name prefix
    ConfigBuilder& name(std::string prefix) {
        config_.name_prefix = std::move(prefix);
        return *this;
    }
    
    /// Set write mode
    ConfigBuilder& mode(WriteMode m) {
        config_.mode = m;
        return *this;
    }
    
    /// Enable async mode (default)
    ConfigBuilder& async() {
        config_.mode = WriteMode::Async;
        return *this;
    }
    
    /// Enable sync mode
    ConfigBuilder& sync() {
        config_.mode = WriteMode::Sync;
        return *this;
    }
    
    /// Set compression (with optional level)
    ConfigBuilder& compression(Compression c, std::optional<int> level = std::nullopt) {
        config_.compression = c;
        if (level.has_value()) {
            config_.compression_level = *level;
        }
        return *this;
    }
    
    /// Enable zstd compression with optional level
    ConfigBuilder& zstd(std::optional<int> level = std::nullopt) {
        return compression(Compression::Zstd, level);
    }
    
    /// Set encryption public key
    ConfigBuilder& encrypt(std::string pub_key) {
        config_.pub_key = std::move(pub_key);
        return *this;
    }
    
    /// Set log retention duration
    ConfigBuilder& max_alive(std::chrono::seconds duration) {
        config_.max_alive_duration = duration;
        return *this;
    }
    
    /// Set async flush interval
    ConfigBuilder& flush_interval(std::chrono::milliseconds interval) {
        config_.flush_interval = interval;
        return *this;
    }
    
    /// Set maximum file size (0 = no limit)
    ConfigBuilder& max_file_size(std::uint64_t size) {
        config_.max_file_size = size;
        return *this;
    }
    
    /// Set cache retention days
    ConfigBuilder& cache_days(int days) {
        config_.cache_days = days;
        return *this;
    }
    
    /// Enable/disable console output
    ConfigBuilder& console(bool enable = true) {
        config_.console_output = enable;
        return *this;
    }
    
    /// Set minimum log level
    ConfigBuilder& level(Level min_level) {
        config_.min_level = min_level;
        return *this;
    }
    
    /// Build with validation (fast, no I/O)
    [[nodiscard]] std::expected<Config, std::vector<ConfigError>> build() const {
        auto result = config_.validate();
        if (!result) {
            return std::unexpected(std::move(result.error()));
        }
        return config_;
    }
    
    /// Build with directory validation (may block - creates directories)
    /// @warning This performs I/O operations. On mobile platforms, consider
    ///          calling this on a background thread to avoid blocking the UI.
    [[nodiscard]] std::expected<Config, std::vector<ConfigError>> build_and_prepare() const {
        auto result = config_.validate_with_dirs();
        if (!result) {
            return std::unexpected(std::move(result.error()));
        }
        return config_;
    }
    
    /// Build without validation (fast, no checks)
    [[nodiscard]] Config build_unchecked() const noexcept {
        return config_;
    }
    
    /// Implicit conversion for backward compatibility
    [[nodiscard]] operator Config() const noexcept {
        return config_;
    }
    
private:
    Config config_;
};

} // namespace logln
