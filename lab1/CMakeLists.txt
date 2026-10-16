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

add_task(1 2
        CLI_SOURCES task2.cpp
        LIB_SOURCES utils.cpp
        TEST_SOURCES task2_test.cpp
)

add_task(1 3
        CLI_SOURCES task3.cpp
        LIB_SOURCES utils.cpp
        TEST_SOURCES task3_test.cpp
)

add_task(1 4
        CLI_SOURCES task4.cpp
        LIB_SOURCES utils.cpp
        TEST_SOURCES task4_test.cpp
)

add_task(1 5
        CLI_SOURCES task5.cpp
        LIB_SOURCES utils.cpp
        TEST_SOURCES task5_test.cpp
)

target_link_libraries(lab1_task5 PRIVATE taywee::args)

add_task(1 6
        CLI_SOURCES task6.cpp
        LIB_SOURCES utils.cpp
        TEST_SOURCES task6_test.cpp
)

add_task(1 7
        CLI_SOURCES task7.cpp
        LIB_SOURCES utils.cpp
        TEST_SOURCES task7_test.cpp
)

target_link_libraries(lab1_task7 PRIVATE taywee::args)
