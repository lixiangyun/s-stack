cmake_minimum_required (VERSION 2.6)
project(example)

set(CMAKE_INSTALL_PREFIX ${PROJECT_SOURCE_DIR})
set(INC_DEST_DIR ${CMAKE_INSTALL_PREFIX}/include)
set(LIB_DEST_DIR ${CMAKE_INSTALL_PREFIX}/lib)

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -O0 -g3 -ggdb3 -gdwarf-2")

include_directories("${PROJECT_BINARY_DIR}")
include_directories("${PROJECT_SOURCE_DIR}/src")

add_subdirectory(src)

# add the executable
add_executable(example example.c main.c)
TARGET_LINK_LIBRARIES(example sstack)

# add the install targets
install (TARGETS example DESTINATION bin)
