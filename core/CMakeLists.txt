cmake_minimum_required(VERSION 3.0)
if(TARGET dap_core)
    return() # The project has already been built.
endif()
project (dap_core)

file(GLOB CORE_SRCS *.c)
file(GLOB CORE_HEADERS *.h)

if(UNIX)
    file(GLOB CORE_UNIX_SRCS unix/*.c)
    file(GLOB CORE_UNIX_HEADERS unix/*.h)
endif()

add_library(${PROJECT_NAME} STATIC ${CORE_SRCS} ${CORE_UNIX_SRCS})

#This paths will be used by project-dependent project libraries
target_include_directories(dap_core INTERFACE .)

if(UNIX)
    target_include_directories(dap_core INTERFACE unix)
endif()
