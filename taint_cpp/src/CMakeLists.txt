add_asan()

add_library(serialization serialization.cpp)
add_library(cmdline cmdline.cpp)
target_link_libraries(cmdline PRIVATE clipp)

add_library(utils utils.cpp)

add_library(analysis analysis.cpp)
target_link_libraries(analysis PRIVATE Triton::triton)

add_executable(taint_main app.cpp)
target_link_libraries(taint_main PRIVATE serialization cmdline utils analysis)
