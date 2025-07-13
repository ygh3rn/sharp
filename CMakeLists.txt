cmake_minimum_required(VERSION 3.12)
project(SharpGS)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Find MCL library
find_path(MCL_INCLUDE_DIR mcl/bn.hpp 
    PATHS /usr/local/include /usr/include
    PATH_SUFFIXES include)

find_library(MCL_LIBRARY mcl
    PATHS /usr/local/lib /usr/lib
    PATH_SUFFIXES lib)

if(NOT MCL_INCLUDE_DIR OR NOT MCL_LIBRARY)
    message(FATAL_ERROR "MCL library not found. Please install MCL first.")
endif()

# Check for PARI/GP
find_program(PARI_GP_EXECUTABLE gp)
if(NOT PARI_GP_EXECUTABLE)
    message(WARNING "PARI/GP (gp) not found. Three squares decomposition will not work.")
else()
    message(STATUS "Found PARI/GP: ${PARI_GP_EXECUTABLE}")
endif()

include_directories(${MCL_INCLUDE_DIR})
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/include)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -O3 -DNDEBUG -march=native")

set(SOURCES
    src/pedersen.cpp
    src/three_squares.cpp
    src/sharp_gs.cpp
)

# Main test executable
add_executable(test_sharp_gs tests/test_sharp_gs.cpp ${SOURCES})
target_link_libraries(test_sharp_gs ${MCL_LIBRARY})

# Benchmark executable
add_executable(benchmark_sharp_gs tests/benchmark_sharp_gs.cpp ${SOURCES})
target_link_libraries(benchmark_sharp_gs ${MCL_LIBRARY})

set_target_properties(test_sharp_gs benchmark_sharp_gs PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}
)

enable_testing()
add_test(NAME sharp_gs_test COMMAND test_sharp_gs)

add_custom_target(run
    COMMAND test_sharp_gs
    DEPENDS test_sharp_gs
    WORKING_DIRECTORY ${CMAKE_BINARY_DIR}
    COMMENT "Running SharpGS test suite"
)

add_custom_target(benchmark
    COMMAND benchmark_sharp_gs
    DEPENDS benchmark_sharp_gs
    WORKING_DIRECTORY ${CMAKE_BINARY_DIR}
    COMMENT "Running SharpGS benchmark suite"
)

message(STATUS "MCL include directory: ${MCL_INCLUDE_DIR}")
message(STATUS "MCL library: ${MCL_LIBRARY}")
message(STATUS "Build type: ${CMAKE_BUILD_TYPE}")
message(STATUS "CXX flags: ${CMAKE_CXX_FLAGS}")