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

# Source files
set(SOURCES
    src/mped.cpp
)

# Test executable for checkpoint 1
add_executable(test_mped tests/test_mped.cpp ${SOURCES})
target_link_libraries(test_mped ${MCL_LIBRARY})

set_target_properties(test_mped PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}
)

# Enable testing
enable_testing()
add_test(NAME mped_test COMMAND test_mped)

# Custom target for running tests
add_custom_target(run_test
    COMMAND test_mped
    DEPENDS test_mped
    WORKING_DIRECTORY ${CMAKE_BINARY_DIR}
    COMMENT "Running MPed test suite"
)

message(STATUS "MCL include directory: ${MCL_INCLUDE_DIR}")
message(STATUS "MCL library: ${MCL_LIBRARY}")
message(STATUS "Build type: ${CMAKE_BUILD_TYPE}")
message(STATUS "CXX flags: ${CMAKE_CXX_FLAGS}")