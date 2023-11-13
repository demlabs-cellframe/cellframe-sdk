cmake_minimum_required(VERSION 3.10)
project (dap_chain_cs_block_pow)
  
file(GLOB DAP_CHAIN_BLOCK_CS_POW_SRCS *.c)
file(GLOB DAP_CHAIN_BLOCK_CS_POW_HEADERS include/*.h)

add_library(${PROJECT_NAME} STATIC ${DAP_CHAIN_BLOCK_CS_POW_SRCS} ${DAP_CHAIN_BLOCK_CS_POW_HEADERS})


target_link_libraries(${PROJECT_NAME} dap_core dap_crypto dap_chain dap_chain_cs_block )
target_include_directories(${PROJECT_NAME} INTERFACE .)

if (INSTALL_SDK)
set_target_properties(${PROJECT_NAME}  PROPERTIES PUBLIC_HEADER "${DAP_CHAIN_BLOCK_CS_POW_HEADERS}")
INSTALL(TARGETS ${PROJECT_NAME} 
        LIBRARY DESTINATION lib/modules/consensus/block-pow/
        ARCHIVE DESTINATION lib/modules/consensus/block-pow/
        PUBLIC_HEADER DESTINATION include/modules/consensus/block-pow/
)
endif()