cmake_minimum_required(VERSION 3.10)
project (dap_chain_net_srv_stake)

file(GLOB DAP_SRV_STAKE_SRCS *.c)

file(GLOB DAP_SRV_STAKE_HEADERS include/*.h)

cellframe_add_library(${PROJECT_NAME} ${DAP_SRV_STAKE_SRCS} HEADERS ${DAP_SRV_STAKE_HEADERS})

target_include_directories(${PROJECT_NAME} INTERFACE .)
target_include_directories(${PROJECT_NAME} PUBLIC include)
# All DAP SDK includes are automatically provided through dap_sdk target
target_link_libraries(${PROJECT_NAME} dap_sdk dap_chain dap_chain_ledger dap_chain_net dap_chain_net_srv dap_compose)

if (INSTALL_SDK)
set_target_properties(${PROJECT_NAME}  PROPERTIES PUBLIC_HEADER "${DAP_SRV_STAKE_HEADERS}")
INSTALL(TARGETS ${PROJECT_NAME} 
        LIBRARY DESTINATION lib/modules/service/stake/
        ARCHIVE DESTINATION lib/modules/service/stake/
        PUBLIC_HEADER DESTINATION include/modules/service/stake/
)
endif()
