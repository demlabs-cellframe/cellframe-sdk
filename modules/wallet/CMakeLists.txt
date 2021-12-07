cmake_minimum_required(VERSION 3.10)
project (dap_chain_wallet)
  
file(GLOB DAP_CHAIN_WALLET_SRCS *.c)
file(GLOB DAP_CHAIN_WALLET_HEADERS include/*.h)

add_library(${PROJECT_NAME} STATIC ${DAP_CHAIN_WALLET_SRCS} ${DAP_CHAIN_WALLET_HEADERS})

target_link_libraries(dap_chain_wallet dap_core dap_crypto dap_chain dap_chain_net)

target_include_directories(dap_chain_wallet INTERFACE .)
target_include_directories(${PROJECT_NAME} PUBLIC include)
