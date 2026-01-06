// SPDX-License-Identifier: MIT
// Copyright (c) 2024 Logln Contributors

#include "sink.hpp"
#include "logln/platform.hpp"

#include <iostream>
#include <atomic>
#include <cstdio>
#include <ctime>

// Platform-specific includes
#ifdef LOGLN_PLATFORM_WINDOWS
    #ifndef WIN32_LEAN_AND_MEAN
        #define WIN32_LEAN_AND_MEAN
    #endif
    #include <Windows.h>
#endif

#ifdef LOGLN_PLATFORM_ANDROID
    #include <android/log.h>
#endif

#ifdef LOGLN_PLATFORM_APPLE
    #include <os/log.h>
    #include <sys/time.h>
    // NSLog is available when compiled as Objective-C++
    #if __OBJC__
        #import <Foundation/Foundation.h>
        #define LOGLN_HAS_NSLOG 1
    #endif
#endif

#ifdef LOGLN_PLATFORM_HARMONYOS
    #include <hilog/log.h>
#endif

namespace logln {

// ============================================================================
// ConsoleSink Implementation (Lock-Free)
// ============================================================================

class ConsoleSink::Impl {
public:
    // Lock-free: use atomic for configuration
    std::atomic<bool> use_colors_{true};
    std::atomic<ConsoleFun> console_fun_{ConsoleFun::Printf};
    
#ifdef LOGLN_PLATFORM_APPLE
    os_log_t os_logger_ = nullptr;
#endif
    
    Impl() {
#ifdef LOGLN_PLATFORM_APPLE
        os_logger_ = os_log_create("com.logln", "default");
        // Default to NSLog on Apple for Xcode console visibility
        console_fun_.store(ConsoleFun::NSLog, std::memory_order_relaxed);
#endif
        
#ifdef LOGLN_PLATFORM_WINDOWS
        // Enable ANSI colors on Windows 10+
        HANDLE hOut = GetStdHandle(STD_OUTPUT_HANDLE);
        if (hOut != INVALID_HANDLE_VALUE) {
            DWORD dwMode = 0;
            if (GetConsoleMode(hOut, &dwMode)) {
                SetConsoleMode(hOut, dwMode | ENABLE_VIRTUAL_TERMINAL_PROCESSING);
            }
        }
#endif
    }
    
    ~Impl() {
#ifdef LOGLN_PLATFORM_APPLE
        // os_log_t is automatically released
#endif
    }
    
    // Lock-free write: console output APIs are thread-safe
    void write(std::string_view data) {
#ifdef LOGLN_PLATFORM_ANDROID
        // Android: __android_log_print is thread-safe
        __android_log_print(ANDROID_LOG_INFO, "logln", "%.*s", 
                           static_cast<int>(data.size()), data.data());
                           
#elif defined(LOGLN_PLATFORM_APPLE)
        // Apple: NSLog/os_log/printf are all thread-safe
        write_apple(data);
        
#elif defined(LOGLN_PLATFORM_HARMONYOS)
        // HarmonyOS: OH_LOG_Print is thread-safe
        OH_LOG_Print(LOG_APP, LOG_INFO, 0, "logln", "%{public}.*s",
                     static_cast<int>(data.size()), data.data());
                     
#elif defined(LOGLN_PLATFORM_WINDOWS)
        // Windows: OutputDebugStringA is thread-safe
        std::string str(data);
        if (!str.empty() && str.back() != '\n') {
            str += '\n';
        }
        OutputDebugStringA(str.c_str());
        // Note: std::cout is not thread-safe, but mixing logs is acceptable
        std::cout << str;
        std::cout.flush();
        
#else
        // Linux/Unix: printf/fflush are thread-safe
        write_printf(data);
#endif
    }
    
#ifdef LOGLN_PLATFORM_APPLE
    void write_apple(std::string_view data) {
        // Atomic load for lock-free configuration read
        switch (console_fun_.load(std::memory_order_relaxed)) {
            case ConsoleFun::OSLog:
                write_oslog(data);
                break;
            case ConsoleFun::NSLog:
                write_nslog(data);
                break;
            case ConsoleFun::Printf:
            default:
                write_printf(data);
                break;
        }
    }
    
    void write_oslog(std::string_view data) {
        if (os_logger_) {
            os_log(os_logger_, "%{public}.*s", 
                   static_cast<int>(data.size()), data.data());
        }
    }
    
    void write_nslog(std::string_view data) {
#ifdef LOGLN_HAS_NSLOG
        @autoreleasepool {
            NSString* nsStr = [[NSString alloc] initWithBytes:data.data()
                                                       length:data.size()
                                                     encoding:NSUTF8StringEncoding];
            if (nsStr) {
                // Remove trailing newline as NSLog adds one
                if ([nsStr hasSuffix:@"\n"]) {
                    nsStr = [nsStr substringToIndex:[nsStr length] - 1];
                }
                NSLog(@"%@", nsStr);
            }
        }
#else
        // Fallback to printf if NSLog not available
        write_printf(data);
#endif
    }
#endif  // LOGLN_PLATFORM_APPLE
    
    void write_printf(std::string_view data) {
        // printf/fflush are POSIX thread-safe
        std::printf("%.*s", static_cast<int>(data.size()), data.data());
        if (!data.empty() && data.back() != '\n') {
            std::printf("\n");
        }
        std::fflush(stdout);
    }
};

ConsoleSink::ConsoleSink() : impl_(std::make_unique<Impl>()) {}
ConsoleSink::~ConsoleSink() = default;

void ConsoleSink::write(std::string_view data) {
    impl_->write(data);
}

void ConsoleSink::flush() {
    std::fflush(stdout);
}

void ConsoleSink::set_use_colors(bool enable) {
    impl_->use_colors_.store(enable, std::memory_order_relaxed);
}

void ConsoleSink::set_console_fun(ConsoleFun fun) {
    impl_->console_fun_.store(fun, std::memory_order_relaxed);
}

ConsoleFun ConsoleSink::console_fun() const {
    return impl_->console_fun_.load(std::memory_order_relaxed);
}

} // namespace logln
