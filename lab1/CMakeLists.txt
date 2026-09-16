project(lab1
        LANGUAGES CXX)

set(CLI_DIR ${CMAKE_CURRENT_SOURCE_DIR}/cli)
set(INCLUDE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/include)
set(SOURCE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/src)
set(TESTS_DIR ${CMAKE_CURRENT_SOURCE_DIR}/tests)

add_task(1 1
        CLI_SOURCES task1.cpp
        LIB_SOURCES utils.cpp
        TEST_SOURCES task1_test.cpp
)
