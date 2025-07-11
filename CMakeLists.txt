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

include_directories(${MCL_INCLUDE_DIR})
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/include)

# Optimization flags
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -O3 -DNDEBUG -march=native")

# Core source files
set(CORE_SOURCES
    src/mped.cpp
    src/masking.cpp
    src/threesquares.cpp
)

# Test executables
add_executable(test_mped tests/test_mped.cpp src/mped.cpp)
target_link_libraries(test_mped ${MCL_LIBRARY})

add_executable(test_masking tests/test_masking.cpp src/mped.cpp src/masking.cpp)
target_link_libraries(test_masking ${MCL_LIBRARY})

add_executable(test_threesquares tests/test_threesquares.cpp src/threesquares.cpp)
target_link_libraries(test_threesquares ${MCL_LIBRARY})

# Set output directory
set_target_properties(test_mped test_masking test_threesquares PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}
)

# Enable testing
enable_testing()
add_test(NAME mped_test COMMAND test_mped)
add_test(NAME masking_test COMMAND test_masking)
add_test(NAME threesquares_test COMMAND test_threesquares)

# Custom targets for testing
add_custom_target(run_checkpoint1
    COMMAND test_mped
    DEPENDS test_mped
    WORKING_DIRECTORY ${CMAKE_BINARY_DIR}
    COMMENT "Running Checkpoint 1: MPed Tests"
)

add_custom_target(run_checkpoint2
    COMMAND test_masking
    DEPENDS test_masking
    WORKING_DIRECTORY ${CMAKE_BINARY_DIR}
    COMMENT "Running Checkpoint 2: Masking Tests"
)

add_custom_target(run_all_tests
    COMMAND test_mped && test_masking && test_threesquares
    DEPENDS test_mped test_masking test_threesquares
    WORKING_DIRECTORY ${CMAKE_BINARY_DIR}
    COMMENT "Running All Tests"
)

message(STATUS "MCL include directory: ${MCL_INCLUDE_DIR}")
message(STATUS "MCL library: ${MCL_LIBRARY}")
message(STATUS "Build type: ${CMAKE_BUILD_TYPE}")
message(STATUS "CXX flags: ${CMAKE_CXX_FLAGS}")