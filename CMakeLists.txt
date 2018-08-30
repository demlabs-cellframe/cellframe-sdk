cmake_minimum_required(VERSION 3.0)
project (dap_core_server C)

add_definitions ("-D_GNU_SOURCE")

add_subdirectory(libdap)

if(BUILD_DAP_CORE_SERVER_TESTS)
    enable_testing()
    add_subdirectory(test)
endif()

file(GLOB SOURCES *.c)
file(GLOB HEADERS *.h)

add_library(${PROJECT_NAME} STATIC ${SOURCES} ${HEADERS})

target_link_libraries(${PROJECT_NAME} ev dap_crypto)
target_include_directories(${PROJECT_NAME} INTERFACE .)
