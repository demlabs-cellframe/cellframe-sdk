project(libdap-server C)
cmake_minimum_required(VERSION 3.0)

if(NOT (${SUBMODULES_NO_BUILD} MATCHES ON))
    if ( NOT ( TARGET dap_core ) )
	add_subdirectory(libdap)
    endif()

    if ( NOT ( TARGET dap_crypto ) )
        add_subdirectory(libdap-crypto)
    endif()

    if ( NOT ( TARGET dap_server_core ) )
        add_subdirectory(libdap-server-core)
    endif()

#    if ( NOT ( TARGET dap_server_udp ) )
#        add_subdirectory(libdap-server-udp)
#    endif()
    
endif()


find_package(PkgConfig)
pkg_check_modules(PC_JSON-C REQUIRED json-c)

add_subdirectory(http_server)
add_subdirectory(enc_server)

if (BUILD_LIB_DAP_SERVER_TESTS)
    enable_testing()
    add_subdirectory(test)
endif()
