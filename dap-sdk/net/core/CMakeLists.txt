cmake_minimum_required(VERSION 3.0)

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
  include_directories(../../../3rdparty/uthash/src/)
  include_directories(../../../3rdparty/wepoll/)
endif()

add_library(${PROJECT_NAME} STATIC ${DAP_SERVER_CORE_HEADERS} ${DAP_SERVER_CORE_SOURCES})

if(WIN32)
  target_link_libraries(${PROJECT_NAME} dap_core dap_crypto)
  target_include_directories(${PROJECT_NAME} INTERFACE ../../../3rdparty/wepoll)
endif()

if(UNIX)
  target_link_libraries(${PROJECT_NAME} dap_core dap_crypto rt)

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

