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

# Find GP/PARI for three squares decomposition
find_program(GP_EXECUTABLE gp
    PATHS /usr/bin /usr/local/bin
    DOC "GP/PARI calculator executable")

if(NOT GP_EXECUTABLE)
    message(WARNING "GP/PARI not found. Three squares decomposition will be limited.")
endif()

include_directories(${MCL_INCLUDE_DIR})
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/include)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -O3 -DNDEBUG -march=native")

set(SOURCES
    src/three_squares.cpp
    src/commitment.cpp
    src/masking.cpp
    src/sharpgs.cpp
)

# Create main library
add_library(sharpgs_lib ${SOURCES})
target_link_libraries(sharpgs_lib ${MCL_LIBRARY})

# Create test executable
add_executable(test_sharpgs tests/test_sharpgs.cpp)
target_link_libraries(test_sharpgs sharpgs_lib ${MCL_LIBRARY})

# Create demo executable
add_executable(demo_sharpgs demo/demo_sharpgs.cpp)
target_link_libraries(demo_sharpgs sharpgs_lib ${MCL_LIBRARY})

set_target_properties(test_sharpgs demo_sharpgs PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}
)

# Enable testing
enable_testing()
add_test(NAME sharpgs_test COMMAND test_sharpgs)

add_custom_target(run
    COMMAND test_sharpgs
    DEPENDS test_sharpgs
    WORKING_DIRECTORY ${CMAKE_BINARY_DIR}
    COMMENT "Running SharpGS test suite"
)

# Copy GP script to build directory
configure_file(${CMAKE_CURRENT_SOURCE_DIR}/scripts/three_squares.gp 
               ${CMAKE_BINARY_DIR}/three_squares.gp COPYONLY)

message(STATUS "MCL include directory: ${MCL_INCLUDE_DIR}")
message(STATUS "MCL library: ${MCL_LIBRARY}")
message(STATUS "GP/PARI executable: ${GP_EXECUTABLE}")
message(STATUS "Build type: ${CMAKE_BUILD_TYPE}")
message(STATUS "CXX flags: ${CMAKE_CXX_FLAGS}")