project(libdap-stream C)
cmake_minimum_required(VERSION 2.8)

if(NOT (${SUBMODULES_NO_BUILD} MATCHES ON))
    set(SUBMODULES_NO_BUILD ON)
    add_subdirectory(libdap)
    add_subdirectory(libdap-server)
    add_subdirectory(libdap-server-core)
    add_subdirectory(libdap-server-udp)
    add_subdirectory(libdap-stream-ch)
endif()

#if(BUILD_DAP_STREAM_TESTS)
    enable_testing()
    add_subdirectory(test)
#endif()

add_subdirectory(session)
add_subdirectory(stream)
