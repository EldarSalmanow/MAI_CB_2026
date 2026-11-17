project(lab3
        LANGUAGES CXX)

set(CLI_DIR ${CMAKE_CURRENT_SOURCE_DIR}/cli)
set(INCLUDE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/include)
set(SOURCE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/src)
set(TESTS_DIR ${CMAKE_CURRENT_SOURCE_DIR}/tests)

add_task(3 1
        CLI_SOURCES task1.cpp
        LIB_SOURCES galois_field.cpp
        TEST_SOURCES task1_test.cpp
)

add_task(3 2
        CLI_SOURCES task2.cpp
        LIB_SOURCES galois_field.cpp rijndael_algorithm.cpp
        TEST_SOURCES task2_test.cpp
)

add_task(3 3
        CLI_SOURCES task3.cpp
        LIB_SOURCES galois_field.cpp rijndael_algorithm.cpp
        TEST_SOURCES task3_test.cpp
)
