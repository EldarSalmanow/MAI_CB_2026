project(lab2
        LANGUAGES CXX)

set(CLI_DIR ${CMAKE_CURRENT_SOURCE_DIR}/cli)
set(INCLUDE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/include)
set(SOURCE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/src)
set(TESTS_DIR ${CMAKE_CURRENT_SOURCE_DIR}/tests)

add_task(2 1
        CLI_SOURCES task1.cpp
        LIB_SOURCES math.cpp
        TEST_SOURCES task1_test.cpp
)

add_task(2 2
        CLI_SOURCES task2.cpp
        LIB_SOURCES math.cpp primality_test.cpp
        TEST_SOURCES task2_test.cpp
)

add_task(2 3
        CLI_SOURCES task3.cpp
        LIB_SOURCES math.cpp primality_test.cpp rsa.cpp
        TEST_SOURCES task3_test.cpp
)

add_task(2 4
        CLI_SOURCES task4.cpp
        LIB_SOURCES math.cpp
        TEST_SOURCES task4_test.cpp
)
