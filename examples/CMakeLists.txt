# examples/CMakeLists.txt

# ============================================================================
# Basic Examples
# ============================================================================

# C++ basic example
add_executable(example_cpp basic_cpp.cpp)
target_link_libraries(example_cpp PRIVATE logln::logln)
target_compile_features(example_cpp PRIVATE cxx_std_23)

# C basic example
add_executable(example_c basic_c.c)
target_link_libraries(example_c PRIVATE logln)
set_target_properties(example_c PROPERTIES
    C_STANDARD 99
    C_STANDARD_REQUIRED ON
)

# ============================================================================
# Advanced Examples (compression, encryption, custom format)
# ============================================================================

# C++ advanced example
add_executable(advanced advanced.cpp)
target_link_libraries(advanced PRIVATE logln::logln)
target_compile_features(advanced PRIVATE cxx_std_23)

# C advanced example
add_executable(advanced_c advanced_c.c)
target_link_libraries(advanced_c PRIVATE logln)
set_target_properties(advanced_c PROPERTIES
    C_STANDARD 99
    C_STANDARD_REQUIRED ON
)
