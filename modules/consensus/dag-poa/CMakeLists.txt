cmake_minimum_required(VERSION 3.10)
project (dap_chain_cs_dag_poa)
  
file(GLOB DAP_CHAIN_DAG_CS_POA_SRCS *.c)
file(GLOB DAP_CHAIN_DAG_CS_POA_HEADERS include/*.h)

add_library(${PROJECT_NAME} STATIC ${DAP_CHAIN_DAG_CS_POA_SRCS} ${DAP_CHAIN_DAG_CS_POA_HEADERS})

target_link_libraries(dap_chain_cs_dag_poa dap_core dap_crypto dap_chain dap_chain_cs_dag dap_chain_net_srv_stake)
target_include_directories(dap_chain_cs_dag_poa INTERFACE .)
target_include_directories(${PROJECT_NAME} PUBLIC include)
