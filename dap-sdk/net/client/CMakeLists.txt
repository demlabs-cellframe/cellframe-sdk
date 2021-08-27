cmake_minimum_required(VERSION 3.0)
project(dap_client)
add_definitions ("-D_GNU_SOURCE")

file(GLOB DAP_CLIENT_SOURCES FILES *.c)
file(GLOB DAP_CLIENT_HEADERS FILES include/*.h)

add_library(${PROJECT_NAME} STATIC ${DAP_CLIENT_HEADERS} ${DAP_CLIENT_SOURCES})


if(DAPSDK_MODULES MATCHES "ssl-support")
    target_link_libraries(${PROJECT_NAME} dap_core dap_crypto dap_server_core dap_http_server dap_enc_server dap_stream dap_session dap_stream_ch json-c wolfssl)
else()
    target_link_libraries(${PROJECT_NAME} dap_core dap_crypto dap_server_core dap_http_server dap_enc_server dap_stream dap_session dap_stream_ch json-c)
endif()
if(UNIX AND NOT ANDROID AND NOT DARWIN)
    target_link_libraries(${PROJECT_NAME} rt)
endif()


target_include_directories(${PROJECT_NAME} PUBLIC include)
target_include_directories(${PROJECT_NAME} PRIVATE .)
target_include_directories(${PROJECT_NAME} PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/../../../3rdparty/uthash/src)

if (${BUILD_DAP_CLIENT_TESTS} MATCHES ON)
    enable_testing()
    add_subdirectory(test)
endif()

