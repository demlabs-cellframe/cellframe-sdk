cmake_minimum_required(VERSION 3.10)

project (dap_core_win32 C)

file(GLOB CORE_SRCS *.c)
file(GLOB CORE_HEADERS *.h)

add_library(${PROJECT_NAME} STATIC ${CORE_SRCS} ${CORE_HEADERS})

target_include_directories(${PROJECT_NAME} INTERFACE .)