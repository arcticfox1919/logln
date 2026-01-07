// SPDX-License-Identifier: MIT
// Logln C++ Basic Example
//
// Build:
//   cmake --build build --config Release
//   cl /std:c++23 /I include examples/basic_cpp.cpp build/Release/logln.lib
//
// Or link with shared library:
//   cl /std:c++23 /DLOGLN_USING_DLL /I include examples/basic_cpp.cpp build/Release/logln.lib

#include <logln/logln.h>
#include <iostream>

int main() {
    // Create logger using ConfigBuilder (fluent API)
    auto config = logln::ConfigBuilder()
        .log_dir("./logs")              // Log output directory
        .name("example")                // Logger name and file prefix
        .level(logln::Level::Debug)     // Minimum log level
        .console(true)                  // Also output to console
        .build();                       // Validate and build

    if (!config) {
        std::cerr << "Config error: ";
        for (auto err : config.error()) {
            std::cerr << logln::config_error_message(err) << "; ";
        }
        std::cerr << "\n";
        return 1;
    }

    // Create logger
    auto* logger = logln::Logger::create(*config);
    if (!logger) {
        std::cerr << "Failed to create logger\n";
        return 1;
    }

    // Log messages at different levels
    logger->debug("Main", "Application started");
    logger->info("Main", "Processing {} items", 42);
    logger->warn("Network", "Connection timeout after {} seconds", 30);
    logger->error("Database", "Query failed: {}", "table not found");

    // Log with custom tag
    logger->info("Config", "Loaded {} settings from {}", 5, "config.json");

    // Flush and cleanup
    logger->flush_sync();
    logln::Logger::release_all();

    std::cout << "Logs written to ./logs/\n";
    return 0;
}
