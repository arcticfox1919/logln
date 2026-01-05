// SPDX-License-Identifier: MIT
// Copyright (c) 2024 Logln Contributors

#pragma once

#include "logln/types.hpp"
#include "logln/config.hpp"

#include <filesystem>
#include <string>
#include <string_view>
#include <vector>
#include <memory>
#include <cstdio>
#include <span>

namespace logln {

// ============================================================================
// Sink Interface - Abstract output destination
// ============================================================================

class ISink {
public:
    virtual ~ISink() = default;
    
    // Write formatted log data (string_view version for convenience)
    virtual void write(std::string_view data) = 0;
    
    // Flush pending writes
    virtual void flush() = 0;
};

// ============================================================================
// File Sink - Writes logs to rotating files
// ============================================================================

class FileSink : public ISink {
public:
    /// @param log_dir Log output directory
    /// @param name_prefix File name prefix (e.g., "myapp" -> "myapp_20241127.log")
    /// @param max_file_size Max file size before rotation (0 = no limit)
    /// @param binary_mode If true, use .blog extension for binary logs (compressed/encrypted)
    ///                    If false, use .log extension for plain text logs
    FileSink(const std::filesystem::path& log_dir,
             const std::string& name_prefix,
             std::uint64_t max_file_size = 0,
             bool binary_mode = false);
    ~FileSink() override;
    
    // Non-copyable
    FileSink(const FileSink&) = delete;
    FileSink& operator=(const FileSink&) = delete;
    
    // ISink interface
    void write(std::string_view data) override;
    void flush() override;
    
    // ========================================================================
    // Configuration
    // ========================================================================
    
    void set_max_size(std::uint64_t size);
    
    // ========================================================================
    // File Management
    // ========================================================================
    
    // Get current log file path
    [[nodiscard]] std::filesystem::path current_path() const;
    
    // Get log files for a specific date
    [[nodiscard]] std::vector<std::filesystem::path> 
    get_files_by_date(int days_ago = 0) const;
    
    // Delete expired log files
    void cleanup_expired(std::chrono::seconds max_age);
    
private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

// ============================================================================
// Console Sink - Writes to stdout/stderr with platform support
// ============================================================================

// Console output function type (Apple platforms only)
enum class ConsoleFun {
    Printf,    // Use printf (default for non-Apple)
    NSLog,     // Use NSLog (shows in Xcode console, iOS/macOS)
    OSLog,     // Use os_log (system log, iOS/macOS)
};

class ConsoleSink : public ISink {
public:
    ConsoleSink();
    ~ConsoleSink() override;
    
    // Non-copyable
    ConsoleSink(const ConsoleSink&) = delete;
    ConsoleSink& operator=(const ConsoleSink&) = delete;
    
    // ISink interface
    void write(std::string_view data) override;
    void flush() override;
    
    // Set whether to use ANSI colors (Linux/macOS)
    void set_use_colors(bool enable);
    
    // Set console output function (Apple platforms)
    // - Printf: uses printf, fastest but no Xcode integration
    // - NSLog: shows in Xcode console, recommended for debugging
    // - OSLog: system unified logging, shows in Console.app
    void set_console_fun(ConsoleFun fun);
    
    // Get current console function
    [[nodiscard]] ConsoleFun console_fun() const;
    
private:
    class Impl;
    std::unique_ptr<Impl> impl_;
};

} // namespace logln
