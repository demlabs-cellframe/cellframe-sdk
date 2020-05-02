project(libdap-stream C)
cmake_minimum_required(VERSION 3.0)

if(NOT SUBMODULES_NO_BUILD)
    if ( NOT ( TARGET dap_core ) )
	add_subdirectory(libdap)
    endif()
    if ( NOT ( TARGET dap_crypto ) )
	add_subdirectory(libdap-crypto)
    endif()
    
    if ( NOT ( TARGET libdap-server ) )
        add_subdirectory(libdap-server)
    endif()

    if ( NOT ( TARGET dap_server_core ) )
	add_subdirectory(libdap-server-core)
    endif()

    if ( NOT ( TARGET dap_server_udp ) )
	add_subdirectory(libdap-server-udp)
    endif()

    if ( NOT ( TARGET dap_stream_ch ) )
	add_subdirectory(libdap-stream-ch)
    endif()
endif()

if(BUILD_DAP_STREAM_TESTS)
    enable_testing()
    add_subdirectory(test)
endif()

add_subdirectory(session)
add_subdirectory(stream)
