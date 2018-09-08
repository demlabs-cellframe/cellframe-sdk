cmake_minimum_required(VERSION 3.0)
project (dap_core_server C)
set(CMAKE_C_STANDARD 11)
add_definitions ("-D_GNU_SOURCE")

add_subdirectory(libdap)

if(BUILD_DAP_CORE_SERVER_TESTS)
    enable_testing()
    add_subdirectory(test)
endif()

file(GLOB CORE_SERVER_SOURCES *.c)
file(GLOB CORE_SERVER_HEADERS *.h)

add_library(${PROJECT_NAME} STATIC ${CORE_SERVER_SOURCES} ${CORE_SERVER_HEADERS})

target_link_libraries(${PROJECT_NAME} pthread ev dap_crypto)
target_include_directories(${PROJECT_NAME} INTERFACE .)
