cmake_minimum_required(VERSION 3.10)
project (dap_chain_type_none)
  
file(GLOB DAP_CHAIN_TYPE_NO_CONSENSUS_SRC *.c)
file(GLOB DAP_CHAIN_TYPE_NO_CONSENSUS_HDR include/*.h)

# Use universal Cellframe library macro (OBJECT library)
cellframe_add_library(${PROJECT_NAME} ${DAP_CHAIN_TYPE_NO_CONSENSUS_SRC} HEADERS ${DAP_CHAIN_TYPE_NO_CONSENSUS_HDR})

target_link_libraries(${PROJECT_NAME} dap_core dap_chain dap_global_db dap_chain_mempool dap_chain_net)
target_include_directories(${PROJECT_NAME} INTERFACE ${CMAKE_CURRENT_SOURCE_DIR})
target_include_directories(${PROJECT_NAME} PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)

if (INSTALL_SDK)
set_target_properties(${PROJECT_NAME}  PROPERTIES PUBLIC_HEADER "${DAP_CHAIN_TYPE_NO_CONSENSUS_HDR}")
INSTALL(TARGETS ${PROJECT_NAME} 
        LIBRARY DESTINATION lib/modules/consensus/none/
        ARCHIVE DESTINATION lib/modules/consensus/none/
        PUBLIC_HEADER DESTINATION include/modules/consensus/none/ 
        )
endif()