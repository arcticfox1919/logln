# examples/CMakeLists.txt

# C++ example
add_executable(example_cpp basic_cpp.cpp)
target_link_libraries(example_cpp PRIVATE logln::logln)
target_compile_features(example_cpp PRIVATE cxx_std_23)

# C example
add_executable(example_c basic_c.c)
target_link_libraries(example_c PRIVATE logln)
set_target_properties(example_c PROPERTIES
    C_STANDARD 99
    C_STANDARD_REQUIRED ON
)
