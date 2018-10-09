cmake_minimum_required(VERSION 2.8)
project (dap_chain_dag)
  
set(DAP_CHAIN_DAG_SRCS 
	dap_chain_dag.c 
        dap_chain_dag_event.c
        )

set(DAP_CHAIN_DAG_HEADERS
        dap_chain_dag.h
        dap_chain_dag_event.h
    )

add_library(${PROJECT_NAME} STATIC ${DAP_CHAIN_DAG_SRCS} ${DAP_CHAIN_DAG_HEADERS})


target_link_libraries(dap_chain_dag dap_core dap_crypto dap_chain dap_chain_crypto )
target_include_directories(dap_chain_dag INTERFACE .)

set(${PROJECT_NAME}_DEFINITIONS CACHE INTERNAL "${PROJECT_NAME}: Definitions" FORCE)

set(${PROJECT_NAME}_INCLUDE_DIRS ${PROJECT_SOURCE_DIR} CACHE INTERNAL "${PROJECT_NAME}: Include Directories" FORCE)
