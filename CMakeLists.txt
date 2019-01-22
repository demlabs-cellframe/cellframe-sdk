cmake_minimum_required(VERSION 3.0)

if(TARGET dap_core_server)
    return() # The project has already been built.
endif()

project (dap_core_server C)
set(CMAKE_C_STANDARD 11)

add_definitions ("-D_GNU_SOURCE")

if(NOT (${SUBMODULES_NO_BUILD} MATCHES ON))
    add_subdirectory(libdap)
    enable_testing()
    add_subdirectory(test)
endif()

file(GLOB CORE_SERVER_SOURCES *.c)
file(GLOB CORE_SERVER_HEADERS *.h)

add_library(${PROJECT_NAME} STATIC ${CORE_SERVER_SOURCES} ${CORE_SERVER_HEADERS})

target_link_libraries(${PROJECT_NAME} pthread ev memcached dap_crypto)
target_include_directories(${PROJECT_NAME} INTERFACE .)
set(${PROJECT_NAME}_DEFINITIONS CACHE INTERNAL "${PROJECT_NAME}: Definitions" FORCE)

set(${PROJECT_NAME}_INCLUDE_DIRS ${PROJECT_SOURCE_DIR} CACHE INTERNAL "${PROJECT_NAME}: Include Directories" FORCE)
