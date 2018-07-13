cmake_minimum_required(VERSION 2.8)
project (dap_core)

file(GLOB CORE_SRCS *.c)
file(GLOB CORE_HEADERS *.h)

add_library(${PROJECT_NAME} STATIC ${CORE_SRCS} ${CORE_HEADERS})

target_link_libraries(${PROJECT_NAME} ev)

#This paths will be used by project-dependent project libraries
target_include_directories(dap_core INTERFACE .)
target_include_directories(dap_core INTERFACE common)
