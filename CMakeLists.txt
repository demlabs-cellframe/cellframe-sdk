cmake_minimum_required(VERSION 3.0)
project(dap_client)
add_definitions ("-D_GNU_SOURCE")

if(NOT (${SUBMODULES_NO_BUILD} MATCHES ON))
    set(SUBMODULES_NO_BUILD ON)
    if ( NOT ( TARGET dap_core ) )
        add_subdirectory(libdap)
    endif()

    if ( NOT ( TARGET dap_crypto ) )
        add_subdirectory(libdap-crypto)
    endif()

    if ( NOT ( TARGET dap_server_core ) )
        add_subdirectory(libdap-server-core)
    endif()

    if ( NOT ( TARGET dap_server ) )
        add_subdirectory(libdap-server)
    endif()

    if ( NOT ( TARGET dap_udp_server ) )
        add_subdirectory(libdap-server-udp)
    endif()

    if ( NOT ( TARGET libdap-stream ) )
        add_subdirectory(libdap-stream)
    endif()

    if ( NOT ( TARGET dap_stream_ch ) )
        add_subdirectory(libdap-stream-ch)
    endif()


endif()

file(GLOB DAP_CLIENT_SOURCES src/*.c)
file(GLOB DAP_CLIENT_HEADERS include/*.h)

if(WIN32)
  include_directories(../libdap/src/win32/)
  include_directories(../3rdparty/wepoll/include/)
  include_directories(../3rdparty/uthash/src/)
  include_directories(../3rdparty/libjson-c/)
  include_directories(../3rdparty/libmagic/src/)
  include_directories(../3rdparty/curl/include/)
endif()

add_library(${PROJECT_NAME} STATIC ${DAP_CLIENT_HEADERS} ${DAP_CLIENT_SOURCES})

if(WIN32)
  target_link_libraries(${PROJECT_NAME} dap_core dap_crypto dap_server_core dap_udp_server dap_http_server dap_enc_server dap_stream dap_session dap_stream_ch ${CMAKE_CURRENT_SOURCE_DIR}/../lib/[x86_64CLANG]/libjson-c[x86_64CLANG].a)
endif()

if(UNIX)
  target_link_libraries(${PROJECT_NAME} dap_core dap_crypto dap_server_core dap_udp_server dap_http_server dap_enc_server dap_stream dap_session dap_stream_ch json-c)

  if(NOT ANDROID)
      target_link_libraries(${PROJECT_NAME} ev)
  endif()
endif()

target_include_directories(${PROJECT_NAME} PUBLIC include)
target_include_directories(${PROJECT_NAME} PRIVATE src)


if (${BUILD_DAP_CLIENT_TESTS} MATCHES ON)
    enable_testing()
    add_subdirectory(test)
endif()

