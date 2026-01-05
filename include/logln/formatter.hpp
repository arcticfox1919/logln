// SPDX-License-Identifier: MIT
// Copyright (c) 2024 Logln Contributors

#pragma once

#include "types.hpp"

#include <string>
#include <string_view>
#include <format>
#include <functional>
#include <memory>

namespace logln {

// ============================================================================
// Format Pattern Tokens
// ============================================================================
// 
// Supported patterns:
//   {level}      - Single letter level (D, I, W, E, F)
//   {Level}      - Full level name (DEBUG, INFO, etc.)
//   {time}       - Timestamp with timezone (YYYY-MM-DD +TZ HH:MM:SS.mmm)
//   {time6}      - Timestamp with 6-digit micros (YYYY-MM-DD HH:MM:SS.uuuuuu)
//   {date}       - Date only (YYYY-MM-DD)
//   {pid}        - Process ID
//   {tid}        - Thread ID
//   {tid*}       - Thread ID with * suffix if main thread
//   {tag}        - Log tag
//   {file}       - Source file name (without path)
//   {path}       - Full source file path
//   {line}       - Source line number
//   {func}       - Function name
//   {msg}        - Log message
//   {n}          - Newline
//
// Default pattern:
//   "[{level}][{time}][{pid},{tid*}][{tag}][{file}:{line},{func}] {msg}{n}"
//
// Example custom pattern (dayjs style):
//   "[{time6} | tag | {Level} | {tag}] {msg}{n}"
//
// ============================================================================

class Formatter {
public:
    // Default format pattern
    static constexpr std::string_view kDefaultPattern = 
        "[{level}][{time}][{pid},{tid*}][{tag}][{file}:{line},{func}] {msg}{n}";
    
    // Minimal pattern for console
    static constexpr std::string_view kConsolePattern = 
        "[{level}][{tag}] {msg}{n}";
    
    // Verbose pattern with full path
    static constexpr std::string_view kVerbosePattern = 
        "[{Level}][{time}][{pid},{tid*}][{tag}][{path}:{line},{func}] {msg}{n}";
    
    Formatter();
    explicit Formatter(std::string_view pattern);
    ~Formatter();
    
    // Non-copyable, movable
    Formatter(const Formatter&) = delete;
    Formatter& operator=(const Formatter&) = delete;
    Formatter(Formatter&&) noexcept;
    Formatter& operator=(Formatter&&) noexcept;
    
    // Set format pattern
    void set_pattern(std::string_view pattern);
    
    // Get current pattern
    [[nodiscard]] std::string_view pattern() const noexcept;
    
    // Format a log record
    [[nodiscard]] std::string format(const Record& record) const;
    
    // Format directly to a buffer (returns bytes written)
    std::size_t format_to(const Record& record, char* buffer, std::size_t size) const;
    
private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

// ============================================================================
// Utility: Extract filename from path
// ============================================================================

[[nodiscard]] constexpr std::string_view extract_filename(std::string_view path) noexcept {
    if (auto pos = path.find_last_of("/\\"); pos != std::string_view::npos) {
        return path.substr(pos + 1);
    }
    return path;
}

} // namespace logln
