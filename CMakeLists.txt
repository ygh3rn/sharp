cmake_minimum_required(VERSION 3.12)
project(Sharp)

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

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -O3 -DNDEBUG -march=native")

set(SOURCES
    src/ntt.cpp
    src/polynomial.cpp
    src/commitments.cpp
    src/sharpgs.cpp
    src/utils.cpp
)

# Main test executable
add_executable(test_sharpgs tests/test_sharpgs.cpp ${SOURCES})
target_link_libraries(test_sharpgs ${MCL_LIBRARY})

# Example executable
add_executable(range_proof_demo examples/range_proof_demo.cpp ${SOURCES})
target_link_libraries(range_proof_demo ${MCL_LIBRARY})

set_target_properties(test_sharpgs range_proof_demo PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}
)

enable_testing()
add_test(NAME sharpgs_test COMMAND test_sharpgs)

add_custom_target(run_tests
    COMMAND test_sharpgs
    DEPENDS test_sharpgs
    WORKING_DIRECTORY ${CMAKE_BINARY_DIR}
    COMMENT "Running SharpGS test suite"
)

add_custom_target(run_demo
    COMMAND range_proof_demo
    DEPENDS range_proof_demo
    WORKING_DIRECTORY ${CMAKE_BINARY_DIR}
    COMMENT "Running range proof demo"
)

message(STATUS "MCL include directory: ${MCL_INCLUDE_DIR}")
message(STATUS "MCL library: ${MCL_LIBRARY}")
message(STATUS "Build type: ${CMAKE_BUILD_TYPE}")
message(STATUS "CXX flags: ${CMAKE_CXX_FLAGS}")