project(libdap-server C)
cmake_minimum_required(VERSION 3.0)

if(NOT SUBMODULES_NO_BUILD)
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

if (ANDROID)
    add_subdirectory(libmagic)
    add_subdirectory(curl)
endif()

add_subdirectory(http_server)
add_subdirectory(enc_server)

if (BUILD_LIB_DAP_SERVER_TESTS)
    enable_testing()
    add_subdirectory(test)
endif()
