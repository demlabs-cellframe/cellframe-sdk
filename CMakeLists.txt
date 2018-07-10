project(dap C)
cmake_minimum_required(VERSION 2.8)

add_subdirectory(core)
add_subdirectory(crypto)

add_library(${PROJECT_NAME} STATIC IMPORTED)
