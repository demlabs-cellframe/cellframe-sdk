cmake_minimum_required(VERSION 3.10)
project (dap_chain_net_srv_stake_pos_delegate)

file(GLOB DAP_SRV_STAKE_POS_DELEGATE_SRCS *.c)

file(GLOB DAP_SRV_STAKE_POS_DELEGATE_HEADERS include/*.h)

add_library(${PROJECT_NAME} STATIC ${DAP_SRV_STAKE_POS_DELEGATE_SRCS} ${DAP_SRV_STAKE_POS_DELEGATE_HEADERS})

target_include_directories(${PROJECT_NAME} INTERFACE .)
target_include_directories(${PROJECT_NAME} PUBLIC include)
target_link_libraries(${PROJECT_NAME} dap_core dap_crypto dap_chain dap_chain_crypto dap_chain_net dap_chain_net_srv dap_chain_cs_dag_poa dap_chain_cs_block_ton dap_chain_cs_block_poa)
