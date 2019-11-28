cmake_minimum_required(VERSION 2.8)
project (dap_chain_wallet)
  
set(DAP_CHAIN_WALLET_SRCS 
  dap_chain_wallet.c 
        dap_chain_coin.c
        dap_chain_wallet_ops.c

        )

set(DAP_CHAIN_WALLET_HEADERS
        dap_chain_coin.h
        dap_chain_wallet.h
        dap_chain_wallet_internal.h
        dap_chain_wallet_ops.h
    )

if(WIN32)
  include_directories(../libdap/src/win32/)
  include_directories(../3rdparty/libmemcached/)
  include_directories(../3rdparty/libmemcached/win32/)
  include_directories(../3rdparty/uthash/src/)
  include_directories(../3rdparty/libjson-c/)
  include_directories(../3rdparty/curl/include/)
  include_directories(../3rdparty/libsqlite3/)
endif()

add_library(${PROJECT_NAME} STATIC ${DAP_CHAIN_WALLET_SRCS} ${DAP_CHAIN_WALLET_HEADERS})

target_link_libraries(dap_chain_wallet dap_core dap_crypto dap_chain dap_chain_crypto dap_chain_net)

target_include_directories(dap_chain_wallet INTERFACE .)

set(${PROJECT_NAME}_DEFINITIONS CACHE INTERNAL "${PROJECT_NAME}: Definitions" FORCE)

set(${PROJECT_NAME}_INCLUDE_DIRS ${PROJECT_SOURCE_DIR} CACHE INTERNAL "${PROJECT_NAME}: Include Directories" FORCE)
