project(libdap-server C)
cmake_minimum_required(VERSION 3.0)

if (ANDROID)
    add_subdirectory(../../../3rdparty/libmagic)
endif()

add_subdirectory(http_server)
add_subdirectory(enc_server)

if (BUILD_LIB_DAP_SERVER_TESTS)
    enable_testing()
    add_subdirectory(test)
endif()
