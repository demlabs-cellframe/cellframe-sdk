cmake_minimum_required(VERSION 2.8)
project (dap_chain_cs_dag)
  
set(DAP_CHAIN_DAG_SRCS 
	dap_chain_cs_dag.c 
        dap_chain_cs_dag_event.c
        )

set(DAP_CHAIN_DAG_HEADERS
        dap_chain_cs_dag.h
        dap_chain_cs_dag_event.h
    )

add_library(${PROJECT_NAME} STATIC ${DAP_CHAIN_DAG_SRCS} ${DAP_CHAIN_DAG_HEADERS})


target_link_libraries(dap_chain_cs_dag dap_core dap_crypto dap_chain dap_chain_net dap_chain_crypto dap_chain_global_db)
target_include_directories(dap_chain_cs_dag INTERFACE .)

