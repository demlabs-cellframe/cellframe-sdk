cmake_minimum_required(VERSION 3.10)
project (dap_chain_type_dag_poa)
  
file(GLOB DAP_CHAIN_DAG_CS_POA_SRCS *.c)
file(GLOB DAP_CHAIN_DAG_CS_POA_HEADERS include/*.h)

# Use universal Cellframe library macro (OBJECT library)
cellframe_add_library(${PROJECT_NAME} ${DAP_CHAIN_DAG_CS_POA_SRCS} HEADERS ${DAP_CHAIN_DAG_CS_POA_HEADERS})

target_link_libraries(${PROJECT_NAME} dap_core dap_crypto dap_chain dap_chain_type_dag dap_timer)
# MERGED: Use current source dir (upstream), NO manual cmd includes (ours)
target_include_directories(${PROJECT_NAME} INTERFACE ${CMAKE_CURRENT_SOURCE_DIR})
target_include_directories(${PROJECT_NAME} PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)

if (INSTALL_SDK)
set_target_properties(${PROJECT_NAME}  PROPERTIES PUBLIC_HEADER "${DAP_CHAIN_DAG_CS_POA_HEADERS}")
INSTALL(TARGETS ${PROJECT_NAME} 
        LIBRARY DESTINATION lib/modules/consensus/dag-poa/
        ARCHIVE DESTINATION lib/modules/consensus/dag-poa/
        PUBLIC_HEADER DESTINATION include/modules/consensus/dag-poa/ 
        )
endif()