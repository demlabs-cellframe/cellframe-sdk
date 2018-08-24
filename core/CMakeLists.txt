cmake_minimum_required(VERSION 3.0)
project (dap_core)

file(GLOB CORE_SRCS *.c)
file(GLOB CORE_HEADERS *.h)

add_library(${PROJECT_NAME} STATIC ${CORE_SRCS} ${CORE_HEADERS})

#This paths will be used by project-dependent project libraries
target_include_directories(dap_core INTERFACE .)

set(${PROJECT_NAME}_INCLUDE_DIRS ${PROJECT_SOURCE_DIR} CACHE INTERNAL "${PROJECT_NAME}: Include Directories" FORCE)
