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

target_include_directories(lab3_task1_lib
        PRIVATE
        ${CMAKE_SOURCE_DIR}/lab1/include
)

target_include_directories(lab3_task1
        PRIVATE
        ${CMAKE_SOURCE_DIR}/lab1/include
)

target_include_directories(lab3_task1_test
        PRIVATE
        ${CMAKE_SOURCE_DIR}/lab1/include
)

add_task(3 2
        CLI_SOURCES task2.cpp
        LIB_SOURCES galois_field.cpp rijndael_algorithm.cpp
        TEST_SOURCES task2_test.cpp
)

target_include_directories(lab3_task2_lib
        PRIVATE
        ${CMAKE_SOURCE_DIR}/lab1/include
)

target_include_directories(lab3_task2
        PRIVATE
        ${CMAKE_SOURCE_DIR}/lab1/include
)

target_include_directories(lab3_task2_test
        PRIVATE
        ${CMAKE_SOURCE_DIR}/lab1/include
)

add_task(3 3
        CLI_SOURCES task3.cpp
        LIB_SOURCES galois_field.cpp rijndael_algorithm.cpp
        TEST_SOURCES task3_test.cpp
)

target_include_directories(lab3_task3_lib
        PRIVATE
        ${CMAKE_SOURCE_DIR}/lab1/include
)

target_include_directories(lab3_task3
        PRIVATE
        ${CMAKE_SOURCE_DIR}/lab1/include
)

target_include_directories(lab3_task3_test
        PRIVATE
        ${CMAKE_SOURCE_DIR}/lab1/include
)
