// SPDX-License-Identifier: MIT
// Copyright (c) 2024 Logln Contributors

#pragma once

#include "logln/types.hpp"

#include <concurrentqueue.h>

#include <thread>
#include <functional>
#include <atomic>
#include <chrono>
#include <optional>
#include <semaphore>
#include <mutex>
#include <condition_variable>
#include <string>
#include <string_view>

namespace logln {

// ============================================================================
// LogEntry - Single log entry for async queue
// ============================================================================

struct LogEntry {
    Level level;
    std::string formatted;
    
    LogEntry() : level(Level::Info) {}
    LogEntry(Level lvl, std::string&& f) 
        : level(lvl), formatted(std::move(f)) {}
};

// ============================================================================
// AsyncWorker - High-performance async log writer
//
// Architecture (2 threads to prevent I/O blocking):
//
//   Producer Threads           Log Thread              Flush Thread
//   ================          ==========              ============
//        |                        |                        |
//        | [lock-free enqueue]    |                        |
//        |----------------------->|                        |
//        |                        | write to mmap buffer   |
//        |                        |----------------------->| 
//        |                        |                        | flush to file
//        |                        |                        | (may block on I/O)
//
// Benefits:
// - Log thread never blocks on file I/O
// - Even if file I/O is slow, logs are written to mmap buffer quickly
// - mmap buffer survives process crashes (OS flushes to disk)
// - Queue won't overflow due to slow I/O
// ============================================================================

class AsyncWorker {
public:
    // Callback types
    using WriteToBufferCallback = std::function<void(LogEntry&)>;
    using FlushToFileCallback = std::function<void()>;
    
    // Initial capacity for preallocation (reduces runtime allocations)
    static constexpr std::size_t kDefaultCapacity = 256;
    
    explicit AsyncWorker(std::size_t initial_capacity = kDefaultCapacity);
    ~AsyncWorker();
    
    // Non-copyable, non-movable
    AsyncWorker(const AsyncWorker&) = delete;
    AsyncWorker& operator=(const AsyncWorker&) = delete;
    AsyncWorker(AsyncWorker&&) = delete;
    AsyncWorker& operator=(AsyncWorker&&) = delete;
    
    // ========================================================================
    // Lifecycle
    // ========================================================================
    
    // Start both worker threads
    // write_cb: Called for each log entry (writes to mmap buffer)
    // flush_cb: Called to flush buffer to file
    void start(WriteToBufferCallback write_cb, FlushToFileCallback flush_cb);
    
    // Stop both worker threads (processes remaining entries)
    void stop();
    
    // Check if running
    [[nodiscard]] bool is_running() const noexcept;
    
    // ========================================================================
    // Enqueue (called from any thread - lock-free)
    // ========================================================================
    
    // Enqueue a log entry (non-blocking, moves the string)
    [[nodiscard]] bool enqueue(Level level, std::string&& formatted);
    
    // ========================================================================
    // Control
    // ========================================================================
    
    // Signal log thread to wake up
    void notify();
    
    // Wait for all pending entries to be written to buffer and flushed
    void wait_flush();
    
    // Set flush interval
    void set_flush_interval(std::chrono::milliseconds interval);
    
    // ========================================================================
    // Statistics
    // ========================================================================
    
    [[nodiscard]] std::size_t size_approx() const noexcept;
    [[nodiscard]] std::uint64_t total_enqueued() const noexcept;
    
private:
    void log_thread_loop();
    void flush_thread_loop();
    
    // Lock-free queue (unbounded, grows as needed)
    moodycamel::ConcurrentQueue<LogEntry> queue_;
    
    // Callbacks
    WriteToBufferCallback write_callback_;
    FlushToFileCallback flush_callback_;
    
    // Worker threads
    std::optional<std::thread> log_thread_;
    std::optional<std::thread> flush_thread_;
    
    // Synchronization for log thread
    std::binary_semaphore log_wake_sem_{0};
    
    // Synchronization for flush thread
    std::binary_semaphore flush_wake_sem_{0};
    std::mutex flush_mutex_;
    std::condition_variable flush_cv_;
    std::atomic<std::uint64_t> flush_generation_{0};
    
    // State
    std::atomic<bool> running_{false};
    std::atomic<bool> stop_requested_{false};
    std::atomic<std::chrono::milliseconds> flush_interval_{std::chrono::minutes{15}};
    
    // Statistics
    std::atomic<std::uint64_t> total_enqueued_{0};
};

} // namespace logln
