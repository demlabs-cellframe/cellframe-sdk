cmake_minimum_required(VERSION 3.10)
project (dap_chain_net_srv_stake)

file(GLOB DAP_SRV_STAKE_SRCS *.c)

file(GLOB DAP_SRV_STAKE_HEADERS include/*.h)

cellframe_add_library(${PROJECT_NAME} ${DAP_SRV_STAKE_SRCS} HEADERS ${DAP_SRV_STAKE_HEADERS})

target_include_directories(${PROJECT_NAME} INTERFACE .)
target_include_directories(${PROJECT_NAME} PUBLIC include)
# Include headers for types (NOT link - breaks cycles)
target_include_directories(${PROJECT_NAME} PRIVATE 
    ${CMAKE_SOURCE_DIR}/modules/compose/include
    ${CMAKE_SOURCE_DIR}/modules/service/xchange/include
    ${CMAKE_SOURCE_DIR}/modules/consensus/esbocs/include
)
# OBJECT library: stake needs wallet + net_srv + net_tx (high-level service)
target_link_libraries(${PROJECT_NAME} dap_sdk dap_chain dap_chain_ledger dap_chain_cs
    dap_chain_wallet dap_chain_net dap_chain_net_srv dap_chain_net_tx dap_common)

if (INSTALL_SDK)
set_target_properties(${PROJECT_NAME}  PROPERTIES PUBLIC_HEADER "${DAP_SRV_STAKE_HEADERS}")
INSTALL(TARGETS ${PROJECT_NAME} 
        LIBRARY DESTINATION lib/modules/service/stake/
        ARCHIVE DESTINATION lib/modules/service/stake/
        PUBLIC_HEADER DESTINATION include/modules/service/stake/
)
endif()
