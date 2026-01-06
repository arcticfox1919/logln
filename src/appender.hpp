// SPDX-License-Identifier: MIT
// Copyright (c) 2024 Logln Contributors
//
// Appender - Internal implementation for log file management
// This is an INTERNAL header, not part of the public API.
// Users should use Logger as the sole entry point.

#pragma once

#include "logln/types.hpp"
#include "logln/config.hpp"

#include <filesystem>
#include <string>
#include <string_view>
#include <vector>
#include <memory>
#include <chrono>
#include <cstdint>
#include <functional>

namespace logln {
namespace detail {

// ============================================================================
// Appender - Internal log file manager (not exposed to users)
// ============================================================================

class Appender {
public:
    // Factory method
    [[nodiscard]] static std::unique_ptr<Appender> create(const Config& config);
    
    ~Appender();
    
    // Non-copyable, non-movable
    Appender(const Appender&) = delete;
    Appender& operator=(const Appender&) = delete;
    Appender(Appender&&) = delete;
    Appender& operator=(Appender&&) = delete;
    
    // ========================================================================
    // Core Operations
    // ========================================================================
    
    void write(const Record& record, std::string&& formatted);
    void flush();
    void flush_sync();
    void close();
    
    // ========================================================================
    // Configuration
    // ========================================================================
    
    void set_mode(WriteMode mode);
    [[nodiscard]] WriteMode mode() const noexcept;
    
    void set_console_output(bool enable);
    [[nodiscard]] bool console_output() const noexcept;
    
    void set_max_file_size(std::uint64_t max_bytes);
    void set_max_alive_duration(std::chrono::seconds duration);
    
    // ========================================================================
    // File Operations
    // ========================================================================
    
    [[nodiscard]] bool get_current_log_path(std::string& out_path) const;
    [[nodiscard]] bool get_current_cache_path(std::string& out_path) const;
    
    [[nodiscard]] std::vector<std::filesystem::path> 
    get_log_files_from_timespan(int days_ago, std::string_view prefix) const;
    
    [[nodiscard]] std::vector<std::filesystem::path> 
    get_all_log_files(bool include_current = false) const;
    
    // ========================================================================
    // File Cleanup
    // ========================================================================
    
    std::size_t remove_log_files(const std::vector<std::filesystem::path>& files);
    std::size_t remove_expired_log_files(int days_ago);
    
    using RemoveCallback = std::function<void(std::size_t)>;
    void remove_log_files_async(const std::vector<std::filesystem::path>& files,
                                RemoveCallback callback = nullptr);
    void remove_expired_log_files_async(int days_ago, RemoveCallback callback = nullptr);

private:
    explicit Appender(const Config& config);
    
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

} // namespace detail
} // namespace logln
