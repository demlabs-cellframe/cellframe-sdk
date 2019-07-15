cmake_minimum_required(VERSION 2.8)
project (dap_chain_global_db)
  
file(GLOB DAP_CHAIN_GLOBAL_DB_SRC *.c)
file(GLOB DAP_CHAIN_GLOBAL_DB_HDR *.h)

if(WIN32)
  include_directories(../libdap/src/win32/)
  include_directories(../3rdparty/libmemcached/)
  include_directories(../3rdparty/libmemcached/win32/)
  include_directories(../3rdparty/wepoll/include/)
  include_directories(../3rdparty/uthash/src/)
  include_directories(../3rdparty/libjson-c/)
  include_directories(../3rdparty/libmagic/src/)
  include_directories(../3rdparty/curl/include/)
  include_directories(../3rdparty/libsqlite3/)
endif()

add_library(${PROJECT_NAME} STATIC ${DAP_CHAIN_GLOBAL_DB_SRC} ${DAP_CHAIN_GLOBAL_DB_HDR})

if(WIN32)
  target_link_libraries(dap_chain_global_db dap_core dap_crypto dap_chain dap_chain_crypto)
endif()
if(UNIX)
  target_link_libraries(dap_chain_global_db dap_core dap_crypto dap_chain dap_chain_crypto ldb talloc tevent sqlite3 ${CMAKE_CURRENT_SOURCE_DIR}/libcuttdb.a)
endif()

target_include_directories(dap_chain_global_db INTERFACE .)

set(${PROJECT_NAME}_DEFINITIONS CACHE INTERNAL "${PROJECT_NAME}: Definitions" FORCE)

set(${PROJECT_NAME}_INCLUDE_DIRS ${PROJECT_SOURCE_DIR} CACHE INTERNAL "${PROJECT_NAME}: Include Directories" FORCE)
