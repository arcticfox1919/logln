// SPDX-License-Identifier: MIT
// Copyright (c) 2024 Logln Contributors

#ifndef LOGLN_UTILS_HPP
#define LOGLN_UTILS_HPP

#include "logln/types.hpp"

#include <cstddef>
#include <string>

namespace logln {

// ============================================================================
// Hex Dump Utilities
// ============================================================================

// Generate hex dump of binary data
// Format: "00000000: 48 65 6c 6c 6f 20  |Hello |"
[[nodiscard]] std::string hex_dump(const void* data, std::size_t len, 
                                    std::size_t bytes_per_line = 16);

// Generate hex dump with log header analysis
[[nodiscard]] std::string dump_with_header(const void* data, std::size_t len);

// ============================================================================
// Time Formatting Utilities
// ============================================================================

// Full format with timezone: "YYYY-MM-DD +TZ HH:MM:SS"
[[nodiscard]] std::string format_time_full(const Timestamp& tv);

// Compact date: "YYYYMMDD"
[[nodiscard]] std::string format_date_compact(const Timestamp& tv);

// Compact datetime with millis: "YYYYMMDD_HHMMSS_mmm"
[[nodiscard]] std::string format_datetime_compact(const Timestamp& tv);

// ISO format with microseconds: "YYYY-MM-DD HH:MM:SS.uuuuuu"
[[nodiscard]] std::string format_timestamp_micros(const Timestamp& tv);

// Full timestamp with timezone and millis: "YYYY-MM-DD +TZ HH:MM:SS.mmm"
[[nodiscard]] std::string format_timestamp(const Timestamp& tv);

// Date only: "YYYY-MM-DD"
[[nodiscard]] std::string format_date(const Timestamp& tv);

} // namespace logln

#endif // LOGLN_UTILS_HPP
