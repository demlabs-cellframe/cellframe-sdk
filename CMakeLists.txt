cmake_minimum_required(VERSION 3.1)
project (dap_udp_server C)

if(NOT (${SUBMODULES_NO_BUILD} MATCHES ON))

#    if ( NOT ( TARGET dap_server_core ) )
#        add_subdirectory(libdap-server-core)
#    endif()

    if ( NOT ( TARGET dap_core ) )
      add_subdirectory(libdap)
    endif()

    if ( NOT ( TARGET dap_server_core ) )
        add_subdirectory(libdap-server-core)
    endif()

    enable_testing()
    add_subdirectory(test)
endif()

set(DAP_UDP_SERVER_SRCS dap_udp_server.c dap_udp_client.h dap_udp_client.c )

if(WIN32)
  include_directories(../libdap/src/win32/)
  include_directories(../3rdparty/wepoll/include/)
  include_directories(../3rdparty/uthash/src/)
  include_directories(../3rdparty/libjson-c/)
  include_directories(../3rdparty/curl/include/)
  #include_directories(../sources/wepoll/)
endif()

add_library(${PROJECT_NAME} STATIC ${DAP_UDP_SERVER_SRCS})

target_link_libraries(${PROJECT_NAME} dap_core dap_server_core )

target_include_directories(${PROJECT_NAME} INTERFACE .)
