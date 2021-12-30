cmake_minimum_required(VERSION 3.10)
project (dap_chain_cs_dag_poc)
  
file(GLOB DAP_CHAIN_CS_DAG_POC_SRCS *.c)
file(GLOB DAP_CHAIN_CS_DAG_POC_HEADERS include/*.h)

add_library(${PROJECT_NAME} STATIC ${DAP_CHAIN_CS_DAG_POC_SRCS} ${DAP_CHAIN_CS_DAG_POC_HEADERS})

target_link_libraries(dap_chain_cs_dag_poc dap_core dap_crypto dap_chain dap_chain_cs_dag dap_chain_net_srv_stake)
target_include_directories(dap_chain_cs_dag_poc INTERFACE .)
target_include_directories(${PROJECT_NAME} PUBLIC include)
