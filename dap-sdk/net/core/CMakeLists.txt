cmake_minimum_required(VERSION 3.10)

project (dap_server_core C)
set(CMAKE_C_STANDARD 11)

add_definitions ("-D_GNU_SOURCE")

if(WIN32)
    file(GLOB DAP_SERVER_CORE_SOURCES *.c ../../../3rdparty/wepoll/*.c)
    file(GLOB DAP_SERVER_CORE_HEADERS include/*.h ../../../3rdparty/wepoll/*.h)
else()
    file(GLOB DAP_SERVER_CORE_SOURCES *.c)
    file(GLOB DAP_SERVER_CORE_HEADERS include/*.h)
endif()

if(WIN32)
  include_directories(../../../modules/net/win32)
endif()

add_library(${PROJECT_NAME} STATIC ${DAP_SERVER_CORE_HEADERS} ${DAP_SERVER_CORE_SOURCES})

if(DAPSDK_MODULES MATCHES "ssl-support")
  target_link_libraries(${PROJECT_NAME} dap_core dap_crypto wolfssl)
else()
  target_link_libraries(${PROJECT_NAME} dap_core dap_crypto)
endif()

if(UNIX)
  if(NOT ANDROID)
      target_link_libraries(${PROJECT_NAME} pthread)
  endif()

endif()

target_include_directories(${PROJECT_NAME} PUBLIC include)
target_include_directories(${PROJECT_NAME} PRIVATE src)
target_include_directories(${PROJECT_NAME} PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/../../../3rdparty/uthash/src)

if (WIN32)
    target_include_directories(${PROJECT_NAME} PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/../../../3rdparty/wepoll)
endif()

if (${BUILD_DAP_SERVER_CORE_TESTS} MATCHES ON)
    enable_testing()
    add_subdirectory(test)
endif()

