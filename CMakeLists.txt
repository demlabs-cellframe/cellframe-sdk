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

file(GLOB DAP_SERVER_CORE_SOURCES src/*.c)
file(GLOB DAP_SERVER_CORE_HEADERS include/*.h)

if(WIN32)
  include_directories(../libdap/src/win32/)
  include_directories(../3rdparty/wepoll/include/)
  include_directories(../3rdparty/uthash/src/)
  include_directories(../3rdparty/libjson-c/)
  include_directories(../3rdparty/libmagic/src/)
  include_directories(../3rdparty/curl/include/)
endif()

add_library(${PROJECT_NAME} STATIC ${DAP_SERVER_CORE_HEADERS} ${DAP_SERVER_CORE_SOURCES})

if(WIN32)
  target_link_libraries(${PROJECT_NAME} dap_core dap_crypto ${CMAKE_CURRENT_SOURCE_DIR}/../lib/[x86_64CLANG]/wepoll[x86_64CLANG].a)
endif()

if(UNIX)
  target_link_libraries(${PROJECT_NAME} dap_core dap_crypto ev)

  if(NOT ANDROID)
      target_link_libraries(${PROJECT_NAME} pthread)
  endif()

endif()

target_include_directories(${PROJECT_NAME} PUBLIC include)
target_include_directories(${PROJECT_NAME} PRIVATE src)


if (${BUILD_DAP_SERVER_CORE_TESTS} MATCHES ON)
    enable_testing()
    add_subdirectory(test)
endif()

