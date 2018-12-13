cmake_minimum_required(VERSION 3.0)

if(TARGET libdap-client)
    return() # The project has already been built.
endif()

project (libdap-client)
set(CMAKE_C_STANDARD 11)

add_subdirectory(libdap)
add_subdirectory(libdap-server)
add_subdirectory(libdap-stream)
add_subdirectory(libdap-stream-ch)

if(BUILD_LIB_DAP_CLIENT_TESTS)
    enable_testing()
    add_subdirectory(test)
endif()


file(GLOB DAP_CLIENT_SRCS *.c)
file(GLOB DAP_CLIENT_HEADERS *.h)

add_library(${PROJECT_NAME} STATIC ${DAP_CLIENT_SRCS} ${DAP_CLIENT_HEADERS})

target_link_libraries(${PROJECT_NAME} dap_crypto dap_core dap_http_server dap_session dap_stream)

target_include_directories(${PROJECT_NAME} INTERFACE .)

