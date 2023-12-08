cmake_minimum_required(VERSION 3.10)
project (dap_chain_cs_block_pos)
  
file(GLOB DAP_CHAIN_CS_BLOCK_POS_SRCS *.c)
file(GLOB DAP_CHAIN_CS_BLOCK_POS_HEADERS include/*.h)

add_library(${PROJECT_NAME} STATIC ${DAP_CHAIN_CS_BLOCK_POS_SRCS} ${DAP_CHAIN_CS_BLOCK_POS_HEADERS})

target_link_libraries(${PROJECT_NAME} dap_core dap_crypto dap_chain dap_chain_cs_blocks dap_chain_net_srv_stake)
target_include_directories(${PROJECT_NAME} INTERFACE .)
target_include_directories(${PROJECT_NAME} PUBLIC include)

if (INSTALL_SDK)
set_target_properties(${PROJECT_NAME}  PROPERTIES PUBLIC_HEADER "${DAP_CHAIN_CS_BLOCK_POS_HEADERS}")
INSTALL(TARGETS ${PROJECT_NAME} 
        LIBRARY DESTINATION lib/modules/consensus/block-pos/
        ARCHIVE DESTINATION lib/modules/consensus/block-pos/
        PUBLIC_HEADER DESTINATION include/modules/consensus/block-pos/
)
endif()