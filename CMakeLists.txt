cmake_minimum_required(VERSION 2.8)
project (dap_chain_dag_cs_poa)
  
set(DAP_CHAIN_DAG_CS_POA_SRCS 
	dap_chain_dag_cs_poa.c 
        )

set(DAP_CHAIN_DAG_CS_POA_HEADERS
        dap_chain_dag_cs_poa.h
    )

add_library(${PROJECT_NAME} STATIC ${DAP_CHAIN_DAG_CS_POA_SRCS} ${DAP_CHAIN_DAG_CS_POA_HEADERS})


target_link_libraries(dap_chain_dag_cs_poa  dap_core dap_crypto dap_chain dap_chain_crypto dap_chain_dag dap_chain_dag_cs )
target_include_directories(dap_chain_dag_cs_poa INTERFACE .)

set(${PROJECT_NAME}_DEFINITIONS CACHE INTERNAL "${PROJECT_NAME}: Definitions" FORCE)

set(${PROJECT_NAME}_INCLUDE_DIRS ${PROJECT_SOURCE_DIR} CACHE INTERNAL "${PROJECT_NAME}: Include Directories" FORCE)
