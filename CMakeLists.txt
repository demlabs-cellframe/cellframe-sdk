cmake_minimum_required(VERSION 3.0)

if(TARGET dap_core_server)
    return() # The project has already been built.
endif()

project (dap_core_server C)
set(CMAKE_C_STANDARD 11)

add_definitions ("-D_GNU_SOURCE")

if(NOT (${SUBMODULES_NO_BUILD} MATCHES ON))
    if ( NOT ( TARGET dap_core ) )
        add_subdirectory(libdap)
    endif()
    if ( NOT ( TARGET dap_crypto ) )
        add_subdirectory(libdap-crypto)
    endif()
    enable_testing()
    add_subdirectory(test)
endif()

file(GLOB CORE_SERVER_SOURCES *.c)
file(GLOB CORE_SERVER_HEADERS *.h)

add_library(${PROJECT_NAME} STATIC ${CORE_SERVER_SOURCES} ${CORE_SERVER_HEADERS})

target_link_libraries(${PROJECT_NAME} pthread ev memcached dap_core dap_crypto)
target_include_directories(${PROJECT_NAME} INTERFACE .)
