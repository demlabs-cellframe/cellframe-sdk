cmake_minimum_required(VERSION 3.0)
project (dap_client)
set(CMAKE_C_STANDARD 11)


if(NOT (${SUBMODULES_NO_BUILD} MATCHES ON))
    add_subdirectory(libdap)
    add_subdirectory(libdap-server-core)
    add_subdirectory(libdap-server)
    add_subdirectory(libdap-stream)
    add_subdirectory(libdap-stream-ch)

    enable_testing()
    add_subdirectory(test)
endif()


file(GLOB DAP_CLIENT_SRCS *.c)
file(GLOB DAP_CLIENT_HEADERS *.h)

add_library(${PROJECT_NAME} STATIC ${DAP_CLIENT_SRCS} ${DAP_CLIENT_HEADERS})

target_link_libraries(${PROJECT_NAME} dap_crypto dap_core dap_http_server dap_session dap_stream)

target_include_directories(${PROJECT_NAME} INTERFACE .)

