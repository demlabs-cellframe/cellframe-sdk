cmake_minimum_required(VERSION 3.0)

project (dap_server_core C)
set(CMAKE_C_STANDARD 11)

add_definitions ("-D_GNU_SOURCE")

if(NOT (${SUBMODULES_NO_BUILD} MATCHES ON))
    set(SUBMODULES_NO_BUILD ON)
    if ( NOT ( TARGET dap_core ) )
        add_subdirectory(libdap)
    endif()

    if ( NOT ( TARGET dap_crypto ) )
        add_subdirectory(libdap-crypto)
    endif()

endif()

file(GLOB DAP_SERVER_CORE_SOURCES src/*.c ../sources/wepoll/*.c)
file(GLOB DAP_SERVER_CORE_HEADERS include/*.h ../sources/wepoll/*.h)

if(WIN32)
  include_directories(../libdap/src/win32/)
  #include_directories(../sources/wepoll/)
  include_directories(../3rdparty/libmemcached/)
  include_directories(../3rdparty/libmemcached/win32/)
  include_directories(../3rdparty/uthash/src/)
  include_directories(../3rdparty/libjson-c/)
  include_directories(../3rdparty/curl/include/)
endif()

add_library(${PROJECT_NAME} STATIC ${DAP_SERVER_CORE_HEADERS} ${DAP_SERVER_CORE_SOURCES})

if(WIN32)
  target_link_libraries(${PROJECT_NAME} dap_core dap_crypto)
endif()

if(UNIX)
  target_link_libraries(${PROJECT_NAME} dap_core dap_crypto pthread memcached ev)
endif()

target_include_directories(${PROJECT_NAME} PUBLIC include)
target_include_directories(${PROJECT_NAME} PRIVATE src)


if (${BUILD_DAP_SERVER_CORE_TESTS} MATCHES ON)
    enable_testing()
    add_subdirectory(test)
endif()

