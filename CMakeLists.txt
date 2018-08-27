cmake_minimum_required(VERSION 3.0)
project (dap_server_core C)

add_subdirectory(libdap)

file(GLOB SOURCES *.c)
file(GLOB HEADERS *.h)

add_library(${PROJECT_NAME} STATIC ${SOURCES} ${HEADERS})

target_link_libraries(${PROJECT_NAME} ev dapclient)
target_include_directories(${PROJECT_NAME} INTERFACE .)
