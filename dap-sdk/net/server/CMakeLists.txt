project(libdap-server C)
cmake_minimum_required(VERSION 3.0)

add_subdirectory(notify_server)
add_subdirectory(http_server)
add_subdirectory(enc_server)
add_subdirectory(json_rpc)

if (BUILD_LIB_DAP_SERVER_TESTS)
    enable_testing()
    add_subdirectory(test)
endif()
