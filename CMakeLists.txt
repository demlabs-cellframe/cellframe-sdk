cmake_minimum_required(VERSION 3.1)
project (dap_udp_server C)

add_subdirectory(libdap-server-core)

if(BUILD_DAP_UDP_SERVER_TESTS)
    enable_testing()
    add_subdirectory(test)
endif()

set(DAP_UDP_SERVER_SRCS dap_udp_server.c dap_udp_client.h dap_udp_client.c)

add_library(${PROJECT_NAME} STATIC ${DAP_UDP_SERVER_SRCS})

target_link_libraries(${PROJECT_NAME} dap_core_server)

target_include_directories(${PROJECT_NAME} INTERFACE .)
