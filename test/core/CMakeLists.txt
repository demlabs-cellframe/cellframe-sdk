cmake_minimum_required(VERSION 3.0)

project(core_test)

file(GLOB SRCS *.c)

if(UNIX)
    file(GLOB PLATROFM_DEP_SRC unix/*.c)
endif()

add_executable(${PROJECT_NAME} ${SRCS} ${PLATROFM_DEP_SRC})

target_link_libraries(core_test dap_test dap_core)

add_test(
    NAME core-test
    COMMAND core_test
)

if(UNIX)
    target_include_directories(${PROJECT_NAME} PRIVATE unix)
endif()
