// SPDX-License-Identifier: MIT
// Copyright (c) 2024 Logln Contributors

#include "async_worker.hpp"

namespace logln {

AsyncWorker::AsyncWorker(std::size_t initial_capacity)
    : queue_(initial_capacity) {}

AsyncWorker::~AsyncWorker() {
    stop();
}

void AsyncWorker::start(WriteToBufferCallback write_cb, FlushToFileCallback flush_cb) {
    if (running_.load(std::memory_order_acquire)) return;
    
    write_callback_ = std::move(write_cb);
    flush_callback_ = std::move(flush_cb);
    running_.store(true, std::memory_order_release);
    stop_requested_.store(false, std::memory_order_release);
    
    // Start log processing thread (high priority - processes queue)
    log_thread_.emplace([this]() {
        log_thread_loop();
    });
    
    // Start flush thread (lower priority - handles file I/O)
    flush_thread_.emplace([this]() {
        flush_thread_loop();
    });
}

void AsyncWorker::stop() {
    if (!running_.load(std::memory_order_acquire)) return;
    
    stop_requested_.store(true, std::memory_order_release);
    running_.store(false, std::memory_order_release);
    
    // Wake up both threads
    log_wake_sem_.release();
    flush_wake_sem_.release();
    
    if (log_thread_ && log_thread_->joinable()) {
        log_thread_->join();
    }
    log_thread_.reset();
    
    if (flush_thread_ && flush_thread_->joinable()) {
        flush_thread_->join();
    }
    flush_thread_.reset();
}

bool AsyncWorker::is_running() const noexcept {
    return running_.load(std::memory_order_acquire);
}

bool AsyncWorker::enqueue(Level level, std::string&& formatted) {
    if (!running_.load(std::memory_order_acquire)) {
        return false;
    }
    
    // Unbounded queue: enqueue always succeeds (unless out of memory)
    queue_.enqueue(LogEntry{level, std::move(formatted)});
    total_enqueued_.fetch_add(1, std::memory_order_relaxed);
    log_wake_sem_.release();
    return true;
}



void AsyncWorker::notify() {
    if (!running_.load(std::memory_order_acquire)) return;
    log_wake_sem_.release();
}

void AsyncWorker::wait_flush() {
    if (!running_.load(std::memory_order_acquire)) return;
    
    auto current_gen = flush_generation_.load(std::memory_order_acquire);
    
    // Wake up both threads
    log_wake_sem_.release();
    flush_wake_sem_.release();
    
    // Wait for flush generation to advance
    std::unique_lock lock(flush_mutex_);
    flush_cv_.wait(lock, [&] {
        return flush_generation_.load(std::memory_order_acquire) > current_gen
            || !running_.load(std::memory_order_acquire);
    });
}

void AsyncWorker::set_flush_interval(std::chrono::milliseconds interval) {
    flush_interval_.store(interval, std::memory_order_release);
}

std::size_t AsyncWorker::size_approx() const noexcept {
    return queue_.size_approx();
}

std::uint64_t AsyncWorker::total_enqueued() const noexcept {
    return total_enqueued_.load(std::memory_order_relaxed);
}

// Log thread: processes queue entries and writes to mmap buffer immediately
void AsyncWorker::log_thread_loop() {
    LogEntry entry;
    
    while (running_.load(std::memory_order_acquire)) {
        // Wait for entries (short timeout to stay responsive)
        (void)log_wake_sem_.try_acquire_for(std::chrono::milliseconds{10});
        
        if (stop_requested_.load(std::memory_order_acquire)) {
            break;
        }
        
        // Process entries ONE BY ONE - write to mmap immediately
        // This ensures crash safety: mmap is flushed by OS on crash
        bool has_fatal = false;
        
        while (queue_.try_dequeue(entry)) {
            if (write_callback_) {
                write_callback_(entry);
            }
            if (entry.level == Level::Fatal) {
                has_fatal = true;
            }
        }
        
        // Trigger immediate flush for fatal logs
        if (has_fatal) {
            flush_wake_sem_.release();
        }
    }
    
    // Final drain - process remaining entries
    while (queue_.try_dequeue(entry)) {
        if (write_callback_) {
            write_callback_(entry);
        }
    }
    
    // Signal flush thread to do final flush
    flush_wake_sem_.release();
}

// Flush thread: periodically flushes buffer to file
// This thread handles potentially slow file I/O
void AsyncWorker::flush_thread_loop() {
    while (running_.load(std::memory_order_acquire)) {
        auto interval = flush_interval_.load(std::memory_order_relaxed);
        (void)flush_wake_sem_.try_acquire_for(interval);
        
        if (stop_requested_.load(std::memory_order_acquire)) {
            break;
        }
        
        // Flush to file (may block on I/O)
        if (flush_callback_) {
            flush_callback_();
        }
        
        // Notify waiters
        {
            std::lock_guard lock(flush_mutex_);
            flush_generation_.fetch_add(1, std::memory_order_release);
        }
        flush_cv_.notify_all();
    }
    
    // Final flush
    if (flush_callback_) {
        flush_callback_();
    }
    
    // Final notification
    {
        std::lock_guard lock(flush_mutex_);
        flush_generation_.fetch_add(1, std::memory_order_release);
    }
    flush_cv_.notify_all();
}

} // namespace logln
