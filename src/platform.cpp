// SPDX-License-Identifier: MIT
// Copyright (c) 2024 Logln Contributors

#include "logln/platform.hpp"

#include <chrono>
#include <cstdint>
#include <ctime>
#include <cstdio>
#include <string>

#ifdef _WIN32
#include <windows.h>
#include <processthreadsapi.h>
#else
#include <unistd.h>
#include <sys/time.h>
#include <pthread.h>
#ifdef __linux__
#include <sys/syscall.h>
#endif
#endif

namespace logln {

// ============================================================================
// Process/Thread ID Functions
// ============================================================================

std::int64_t get_pid() noexcept {
#ifdef _WIN32
    return static_cast<std::int64_t>(GetCurrentProcessId());
#else
    return static_cast<std::int64_t>(getpid());
#endif
}

std::int64_t get_tid() noexcept {
#ifdef _WIN32
    return static_cast<std::int64_t>(GetCurrentThreadId());
#elif defined(__APPLE__)
    std::uint64_t tid = 0;
    pthread_threadid_np(nullptr, &tid);
    return static_cast<std::int64_t>(tid);
#elif defined(__linux__)
    return static_cast<std::int64_t>(syscall(SYS_gettid));
#else
    return static_cast<std::int64_t>(pthread_self());
#endif
}

std::int64_t get_main_tid() noexcept {
    static std::int64_t main_tid = get_tid();
    return main_tid;
}

// ============================================================================
// Timestamp Functions
// ============================================================================

Timestamp get_timestamp() noexcept {
    return Timestamp::now();
}

std::uint64_t get_tick_count() noexcept {
    using namespace std::chrono;
    return static_cast<std::uint64_t>(
        duration_cast<milliseconds>(
            steady_clock::now().time_since_epoch()
        ).count()
    );
}

// ============================================================================
// Time Formatting Functions
// ============================================================================

std::string format_time_full(const Timestamp& tv) {
    std::time_t sec = static_cast<std::time_t>(tv.tv_sec);
    std::tm tm_buf{};
#ifdef _WIN32
    localtime_s(&tm_buf, &sec);
    double tz_offset = -_timezone / 3600.0;
#else
    localtime_r(&sec, &tm_buf);
    double tz_offset = tm_buf.tm_gmtoff / 3600.0;
#endif
    
    return std::format("{:04d}-{:02d}-{:02d} {:+.1f} {:02d}:{:02d}:{:02d}",
        1900 + tm_buf.tm_year, 1 + tm_buf.tm_mon, tm_buf.tm_mday,
        tz_offset, tm_buf.tm_hour, tm_buf.tm_min, tm_buf.tm_sec);
}

std::string format_date_compact(const Timestamp& tv) {
    std::time_t sec = static_cast<std::time_t>(tv.tv_sec);
    std::tm tm_buf{};
#ifdef _WIN32
    localtime_s(&tm_buf, &sec);
#else
    localtime_r(&sec, &tm_buf);
#endif
    
    return std::format("{:04d}{:02d}{:02d}",
        1900 + tm_buf.tm_year,
        1 + tm_buf.tm_mon,
        tm_buf.tm_mday);
}

std::string format_datetime_compact(const Timestamp& tv) {
    std::time_t sec = static_cast<std::time_t>(tv.tv_sec);
    std::tm tm_buf{};
#ifdef _WIN32
    localtime_s(&tm_buf, &sec);
#else
    localtime_r(&sec, &tm_buf);
#endif
    
    int millis = static_cast<int>(tv.tv_usec / 1000);
    
    return std::format("{:04d}{:02d}{:02d}_{:02d}{:02d}{:02d}_{:03d}",
        1900 + tm_buf.tm_year,
        1 + tm_buf.tm_mon,
        tm_buf.tm_mday,
        tm_buf.tm_hour,
        tm_buf.tm_min,
        tm_buf.tm_sec,
        millis);
}

std::string format_timestamp_micros(const Timestamp& tv) {
    std::time_t sec = static_cast<std::time_t>(tv.tv_sec);
    std::tm tm_buf{};
#ifdef _WIN32
    localtime_s(&tm_buf, &sec);
#else
    localtime_r(&sec, &tm_buf);
#endif
    
    // 6-digit microseconds (SSS000 format where last 3 are always 0 for millisecond precision)
    // or full microsecond if available
    int micros = static_cast<int>(tv.tv_usec);
    
    return std::format("{:04d}-{:02d}-{:02d} {:02d}:{:02d}:{:02d}.{:06d}",
        1900 + tm_buf.tm_year,
        1 + tm_buf.tm_mon,
        tm_buf.tm_mday,
        tm_buf.tm_hour,
        tm_buf.tm_min,
        tm_buf.tm_sec,
        micros);
}

std::string format_timestamp(const Timestamp& tv) {
    std::time_t sec = static_cast<std::time_t>(tv.tv_sec);
    std::tm tm_buf{};
    
#ifdef _WIN32
    localtime_s(&tm_buf, &sec);
    double tz_offset = static_cast<double>(-_timezone) / 3600.0;
#else
    localtime_r(&sec, &tm_buf);
    double tz_offset = tm_buf.tm_gmtoff / 3600.0;
#endif
    
    return std::format("{:04d}-{:02d}-{:02d} {:+.1f} {:02d}:{:02d}:{:02d}.{:03d}",
        1900 + tm_buf.tm_year,
        1 + tm_buf.tm_mon,
        tm_buf.tm_mday,
        tz_offset,
        tm_buf.tm_hour,
        tm_buf.tm_min,
        tm_buf.tm_sec,
        static_cast<int>(tv.tv_usec / 1000));
}

std::string format_date(const Timestamp& tv) {
    std::time_t sec = static_cast<std::time_t>(tv.tv_sec);
    std::tm tm_buf{};
    
#ifdef _WIN32
    localtime_s(&tm_buf, &sec);
#else
    localtime_r(&sec, &tm_buf);
#endif
    
    return std::format("{:04d}-{:02d}-{:02d}",
        1900 + tm_buf.tm_year,
        1 + tm_buf.tm_mon,
        tm_buf.tm_mday);
}

} // namespace logln
