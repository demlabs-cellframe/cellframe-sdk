cmake_minimum_required(VERSION 3.1)
project (dap_chain_dht C)
  
set(DAP_CHAIN_DHT_SRC
            dap_chain_dht.c
    )
set(DAP_CHAIN_DHT_HDR
        include/dap_chain_dht.h
    )
set(DAP_CHAIN_GLOBAL_DB_LIBS dap_core dap_crypto dap_chain)

add_library(${PROJECT_NAME} STATIC ${DAP_CHAIN_DHT_SRC} ${DAP_CHAIN_DHT_HDR})

target_link_libraries(${PROJECT_NAME}  ${DAP_CHAIN_DHT_LIBS})

target_include_directories(${PROJECT_NAME} INTERFACE .)
target_include_directories(${PROJECT_NAME} PUBLIC include)

