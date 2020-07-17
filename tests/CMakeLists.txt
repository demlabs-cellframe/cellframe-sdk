cmake_minimum_required(VERSION 3.0)

project(cellframe_sdk_test)

set(CMAKE_C_STANDARD 11)
file(GLOB SRCS *.c)
file(GLOB HEADERS *.h)

add_executable(${PROJECT_NAME} ${SRCS} ${HEADERS} )
target_link_libraries(${PROJECT_NAME} dap_test cellframe-sdk)
add_test(
    NAME ${PROJECT_NAME}
    COMMAND ${PROJECT_NAME}
)
