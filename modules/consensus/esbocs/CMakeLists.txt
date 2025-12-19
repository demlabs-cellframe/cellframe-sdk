cmake_minimum_required(VERSION 3.10)
project (dap_chain_cs_esbocs)
  
file(GLOB DAP_CHAIN_ESBOCS_SRCS *.c)
file(GLOB DAP_CHAIN_CS_ESBOCS_HEADERS include/*.h)

# Use universal Cellframe library macro
cellframe_add_library(${PROJECT_NAME} ${DAP_CHAIN_ESBOCS_SRCS} HEADERS ${DAP_CHAIN_CS_ESBOCS_HEADERS})

target_include_directories(${PROJECT_NAME} INTERFACE .)
target_include_directories(${PROJECT_NAME} PUBLIC include)
# Stake headers for validator TYPES (uses Validator API for functions)
target_include_directories(${PROJECT_NAME} PRIVATE ${CMAKE_SOURCE_DIR}/modules/service/stake/include)



# OBJECT library: use validator API instead of direct stake dependency
target_link_libraries(${PROJECT_NAME} dap_core dap_crypto dap_chain dap_chain_cs dap_chain_ledger dap_link_manager
    dap_chain_type_blocks dap_chain_mempool dap_chain_net dap_chain_net_srv)
# NO dap_chain_net_srv_stake - use validator API from dap_chain_cs

if (INSTALL_SDK)
set_target_properties(${PROJECT_NAME}  PROPERTIES PUBLIC_HEADER "${DAP_CHAIN_CS_ESBOCS_HEADERS}")
INSTALL(TARGETS ${PROJECT_NAME} 
        LIBRARY DESTINATION lib/modules/consensus/esbocs/
        ARCHIVE DESTINATION lib/modules/consensus/esbocs/
        PUBLIC_HEADER DESTINATION include/modules/consensus/esbocs/ 
        )
endif()
