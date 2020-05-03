cmake_minimum_required(VERSION 2.8)
project (dap_chain_cs_no_consensus)
  
file(GLOB DAP_CHAIN_CS_NO_CONSENSUS_SRC *.c)
file(GLOB DAP_CHAIN_CS_NO_CONSENSUS_HDR include/*.h)

if(WIN32)
  include_directories(../../../3rdparty/uthash/src/)
endif()

add_library(${PROJECT_NAME} STATIC ${DAP_CHAIN_CS_NO_CONSENSUS_SRC} ${DAP_CHAIN_CS_NO_CONSENSUS_HDR})

target_link_libraries(dap_chain_gdb dap_core dap_chain dap_chain_global_db dap_chain_mempool dap_chain_net)
target_include_directories(dap_chain_gdb INTERFACE .)
