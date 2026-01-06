// SPDX-License-Identifier: MIT
// Copyright (c) 2024 Logln Contributors

#include "logln/platform.hpp"

#include <chrono>

#ifdef _WIN32
#include <windows.h>
#include <processthreadsapi.h>
#else
#include <unistd.h>
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

} // namespace logln
