cmake_minimum_required(VERSION 3.28)
project(MAI_CB_2026)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(args REQUIRED)
find_package(Boost REQUIRED)

include_directories(${args_INCLUDE_DIRS})
include_directories(${Boost_INCLUDE_DIRS})

include(cmake/Utils.cmake)
setup_project()

add_subdirectory(lab1)
add_subdirectory(lab2)
