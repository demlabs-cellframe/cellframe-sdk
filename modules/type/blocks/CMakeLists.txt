cmake_minimum_required(VERSION 3.10)
project (dap_chain_type_blocks)
  
file(GLOB DAP_CHAIN_TYPE_BLOCKS_SRCS *.c)
file(GLOB DAP_CHAIN_TYPE_BLOCKS_HEADERS include/*.h)

# Use universal Cellframe library macro (OBJECT library)
cellframe_add_library(${PROJECT_NAME} ${DAP_CHAIN_TYPE_BLOCKS_SRCS} HEADERS ${DAP_CHAIN_TYPE_BLOCKS_HEADERS})

target_include_directories(${PROJECT_NAME} PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/../../net/include)
target_include_directories(${PROJECT_NAME} PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/../../net/core/include)
target_include_directories(${PROJECT_NAME} PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/../../governance/include)

if(BUILD_CELLFRAME_SDK_TESTS)
endif()

# OBJECT library: blocks needs ONLY mempool (NO net - blocks are low-level chain type)
target_link_libraries(${PROJECT_NAME} dap_core dap_crypto dap_chain dap_cli_server dap_chain_cs dap_chain_ledger 
    dap_chain_mempool dap_common)
target_include_directories(${PROJECT_NAME} INTERFACE ${CMAKE_CURRENT_SOURCE_DIR})
target_include_directories(${PROJECT_NAME} PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)

if (INSTALL_SDK)
set_target_properties(${PROJECT_NAME}  PROPERTIES PUBLIC_HEADER "${DAP_CHAIN_TYPE_BLOCKS_HEADERS}")
INSTALL(TARGETS ${PROJECT_NAME} 
        LIBRARY DESTINATION lib/modules/type/blocks/
        ARCHIVE DESTINATION lib/modules/type/blocks/
        PUBLIC_HEADER DESTINATION include/modules/type/blocks/
)
endif()
