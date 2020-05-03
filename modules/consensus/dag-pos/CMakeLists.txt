cmake_minimum_required(VERSION 2.8)
project (dap_chain_cs_dag_pos)
  
set(DAP_CHAIN_CS_DAG_POS_SRCS *.c)
set(DAP_CHAIN_CS_DAG_POS_HEADERS include/*.h)

if(WIN32)
  include_directories(../../../3rdparty/wepoll/)
  include_directories(../../../3rdparty/uthash/src/)
endif()

add_library(${PROJECT_NAME} STATIC ${DAP_CHAIN_CS_DAG_POS_SRCS} ${DAP_CHAIN_CS_DAG_POS_HEADERS})

target_link_libraries(dap_chain_cs_dag_pos dap_core dap_crypto dap_chain dap_chain_crypto dap_chain_cs_dag )
target_include_directories(dap_chain_cs_dag_pos INTERFACE .)
