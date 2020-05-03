cmake_minimum_required(VERSION 3.0)
project(dap_client)
add_definitions ("-D_GNU_SOURCE")

file(GLOB DAP_CLIENT_SOURCES FILES *.c)
file(GLOB DAP_CLIENT_HEADERS FILES include/*.h)

if(WIN32)
  include_directories(../../../3rdparty/wepoll/)
  include_directories(../../../3rdparty/uthash/src/)
endif()

add_library(${PROJECT_NAME} STATIC ${DAP_CLIENT_HEADERS} ${DAP_CLIENT_SOURCES})

target_link_libraries(${PROJECT_NAME} dap_core dap_crypto dap_server_core dap_udp_server dap_http_server dap_enc_server dap_stream dap_session dap_stream_ch json-c)

if(UNIX AND NOT ANDROID)
    target_link_libraries(${PROJECT_NAME} ev)
endif()


target_include_directories(${PROJECT_NAME} PUBLIC include)
target_include_directories(${PROJECT_NAME} PRIVATE .)


if (${BUILD_DAP_CLIENT_TESTS} MATCHES ON)
    enable_testing()
    add_subdirectory(test)
endif()

