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

# Find required system libraries
find_package(Threads REQUIRED)

# Include directories
include_directories(${MCL_INCLUDE_DIR})
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/include)

# Compiler flags
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -O3 -DNDEBUG -march=native -Wall -Wextra")

# Add debug flags for debug builds
set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} -g -O0 -DDEBUG")

# Source files
set(SOURCES
    src/groups.cpp
    src/polynomial.cpp
    src/commitments.cpp
    src/masking.cpp
    src/utils.cpp
    src/sharp_gs.cpp
)

# Main executable
add_executable(test_sharp_gs tests/test_sharp_gs.cpp ${SOURCES})
target_link_libraries(test_sharp_gs ${MCL_LIBRARY} Threads::Threads)

# Add compile definitions
target_compile_definitions(test_sharp_gs PRIVATE MCL_DONT_USE_OPENSSL)

set_target_properties(test_sharp_gs PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}
)

# Demo executable
add_executable(sharp_gs_demo examples/demo.cpp ${SOURCES})
target_link_libraries(sharp_gs_demo ${MCL_LIBRARY} Threads::Threads)

# Add compile definitions
target_compile_definitions(sharp_gs_demo PRIVATE MCL_DONT_USE_OPENSSL)

set_target_properties(sharp_gs_demo PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}
)

# Enable testing
enable_testing()
add_test(NAME sharp_gs_test COMMAND test_sharp_gs)

# Custom target for running tests
add_custom_target(run
    COMMAND test_sharp_gs
    DEPENDS test_sharp_gs
    WORKING_DIRECTORY ${CMAKE_BINARY_DIR}
    COMMENT "Running SharpGS test suite"
)

# Custom target for running demo
add_custom_target(demo
    COMMAND sharp_gs_demo
    DEPENDS sharp_gs_demo
    WORKING_DIRECTORY ${CMAKE_BINARY_DIR}
    COMMENT "Running SharpGS demo"
)

# Clean target
add_custom_target(clean-all
    COMMAND ${CMAKE_BUILD_TOOL} clean
    COMMAND ${CMAKE_COMMAND} -E remove_directory ${CMAKE_BINARY_DIR}/CMakeFiles
    COMMAND ${CMAKE_COMMAND} -E remove ${CMAKE_BINARY_DIR}/CMakeCache.txt
    COMMENT "Cleaning all build files"
)

# Status messages
message(STATUS "MCL include directory: ${MCL_INCLUDE_DIR}")
message(STATUS "MCL library: ${MCL_LIBRARY}")
message(STATUS "Build type: ${CMAKE_BUILD_TYPE}")
message(STATUS "CXX flags: ${CMAKE_CXX_FLAGS}")

# Installation (optional)
install(TARGETS test_sharp_gs sharp_gs_demo
    RUNTIME DESTINATION bin
)

install(DIRECTORY include/
    DESTINATION include/sharp_gs
    FILES_MATCHING PATTERN "*.h"
)