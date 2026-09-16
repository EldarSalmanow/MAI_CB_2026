function(setup_project)
    include(FetchContent)

    FetchContent_Declare(
            googletest
            GIT_REPOSITORY https://github.com/google/googletest.git
            GIT_TAG        v1.17.0
    )
    FetchContent_MakeAvailable(googletest)

    add_library(GTest::GTest
            INTERFACE
            IMPORTED
    )

    target_link_libraries(GTest::GTest
            INTERFACE
            gtest_main
    )

    enable_testing()
endfunction()

function(add_task LAB_NUM TASK_NUM)
    # Parsing arguments

    cmake_parse_arguments(ARG "" "" "CLI_SOURCES;LIB_SOURCES;TEST_SOURCES" ${ARGN})

    set(TASK${TASK_NUM}_CLI_SOURCES)
    foreach(SOURCE ${ARG_CLI_SOURCES})
        list(APPEND
                TASK${TASK_NUM}_CLI_SOURCES
                ${CLI_DIR}/${SOURCE}
        )
    endforeach()

    set(TASK${TASK_NUM}_LIB_SOURCES)
    foreach(SOURCE ${ARG_LIB_SOURCES})
        list(APPEND
                TASK${TASK_NUM}_LIB_SOURCES
                ${SOURCE_DIR}/task${TASK_NUM}/${SOURCE}
        )
    endforeach()

    set(TASK${TASK_NUM}_TEST_SOURCES)
    foreach(SOURCE ${ARG_TEST_SOURCES})
        list(APPEND
                TASK${TASK_NUM}_TEST_SOURCES
                ${TESTS_DIR}/${SOURCE}
        )
    endforeach()

    # Adding library

    if (TASK${TASK_NUM}_LIB_SOURCES)
        add_library(lab${LAB_NUM}_task${TASK_NUM}_lib
                ${TASK${TASK_NUM}_LIB_SOURCES}
        )

        target_include_directories(lab${LAB_NUM}_task${TASK_NUM}_lib
                PRIVATE
                ${INCLUDE_DIR}
        )
    endif()

    # Adding CLI app

    add_executable(lab${LAB_NUM}_task${TASK_NUM}
            ${TASK${TASK_NUM}_CLI_SOURCES}
    )

    target_include_directories(lab${LAB_NUM}_task${TASK_NUM}
            PRIVATE
            ${INCLUDE_DIR}
    )

    if (TASK${TASK_NUM}_LIB_SOURCES)
        target_link_libraries(lab${LAB_NUM}_task${TASK_NUM}
                PRIVATE
                lab${LAB_NUM}_task${TASK_NUM}_lib
        )
    endif()

    # Adding tests

    add_executable(lab${LAB_NUM}_task${TASK_NUM}_test
            ${TASK${TASK_NUM}_TEST_SOURCES}
    )

    target_include_directories(lab${LAB_NUM}_task${TASK_NUM}_test
            PRIVATE
            GTest::GTest
            ${INCLUDE_DIR}
    )

    target_link_libraries(lab${LAB_NUM}_task${TASK_NUM}_test
            PRIVATE
            GTest::GTest
    )

    if (TASK${TASK_NUM}_LIB_SOURCES)
        target_link_libraries(lab${LAB_NUM}_task${TASK_NUM}_test
                PRIVATE
                lab${LAB_NUM}_task${TASK_NUM}_lib
        )
    endif()

    add_test(
            NAME lab${LAB_NUM}_task${TASK_NUM}_tests
            COMMAND lab${LAB_NUM}_task${TASK_NUM}_test
    )
endfunction()
