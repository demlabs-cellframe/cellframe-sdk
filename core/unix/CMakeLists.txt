cmake_minimum_required(VERSION 3.0)

project (dap_core_unix)

file(GLOB CORE_UNIX_SRCS *.c)
file(GLOB CORE_UNIX_HEADERS *.h)

add_library(${PROJECT_NAME} STATIC ${CORE_UNIX_SRCS} ${CORE_UNIX_HEADERS})

target_link_libraries(${PROJECT_NAME} dap_core pthread)

target_include_directories(dap_core_unix INTERFACE .)
