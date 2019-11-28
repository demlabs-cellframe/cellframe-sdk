cmake_minimum_required(VERSION 2.8)
project (dap_chain_net_srv_app_db)
  
set(DAP_CHAIN_NET_SRV_APP_DB_SRCS 
  dap_chain_net_srv_app_db.c 
        )

set(DAP_CHAIN_NET_SRV_APP_DB_HEADERS
        dap_chain_net_srv_app_db.h
    )

if(WIN32)
  include_directories(../libdap/src/win32/)
  include_directories(../3rdparty/wepoll/include/)
  include_directories(../3rdparty/uthash/src/)
  include_directories(../3rdparty/libjson-c/)
  include_directories(../3rdparty/curl/include/)
  include_directories(../3rdparty/libsqlite3/)
endif()

add_library(${PROJECT_NAME} STATIC ${DAP_CHAIN_NET_SRV_APP_DB_SRCS} ${DAP_CHAIN_NET_SRV_APP_DB_HEADERS})

target_link_libraries(dap_chain_net_srv_app_db dap_core dap_crypto dap_chain dap_chain_crypto dap_chain_net dap_chain_net_srv dap_chain_net_srv_app)
target_include_directories(dap_chain_net_srv_app_db INTERFACE .)

set(${PROJECT_NAME}_DEFINITIONS CACHE INTERNAL "${PROJECT_NAME}: Definitions" FORCE)

set(${PROJECT_NAME}_INCLUDE_DIRS ${PROJECT_SOURCE_DIR} CACHE INTERNAL "${PROJECT_NAME}: Include Directories" FORCE)
