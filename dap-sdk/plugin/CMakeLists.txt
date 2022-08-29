cmake_minimum_required(VERSION 3.0)
project(dap_plugin C)

set(CMAKE_VERBOSE_MAKEFILE ON)
set(CMAKE_COLOR_MAKEFILE   ON)
set(CMAKE_C_STANDARD 11)

file(GLOB DAP_PLUGIN_SRCS src/*.c)
file(GLOB DAP_PLUGIN_HEADERS include/*.h)

add_library(${PROJECT_NAME} STATIC ${DAP_PLUGIN_SRCS} ${DAP_PLUGIN_HEADERS})

target_link_libraries(${PROJECT_NAME})

target_link_libraries(${PROJECT_NAME} dap_core dap_cli_server )

if(NOT WIN32)
    target_link_libraries(${PROJECT_NAME} dl )
endif()

target_include_directories(${PROJECT_NAME} PUBLIC include/ )

