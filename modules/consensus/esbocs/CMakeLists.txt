cmake_minimum_required(VERSION 3.10)
project (dap_chain_cs_esbocs)
  
file(GLOB DAP_CHAIN_ESBOCS_SRCS *.c)
file(GLOB DAP_CHAIN_CS_ESBOCS_HEADERS include/*.h)

add_library(${PROJECT_NAME} STATIC ${DAP_CHAIN_ESBOCS_SRCS} ${DAP_CHAIN_CS_ESBOCS_HEADERS})

target_include_directories(${PROJECT_NAME} INTERFACE .)
target_include_directories(${PROJECT_NAME} PUBLIC include)
target_link_libraries(${PROJECT_NAME} dap_core dap_crypto dap_chain dap_chain_cs_blocks dap_chain_net_srv_stake)

if (INSTALL_SDK)
set_target_properties(${PROJECT_NAME}  PROPERTIES PUBLIC_HEADER "${DAP_CHAIN_CS_ESBOCS_HEADERS}")
INSTALL(TARGETS ${PROJECT_NAME} 
        LIBRARY DESTINATION lib/modules/consensus/esbocs/
        ARCHIVE DESTINATION lib/modules/consensus/esbocs/
        PUBLIC_HEADER DESTINATION include/modules/consensus/esbocs/ 
        )
endif()
