cmake_minimum_required(VERSION 3.10)
project (dap_chain_net_srv_stake)

# Temporarily exclude problematic file with syntax errors
# file(GLOB DAP_SRV_STAKE_SRCS *.c)
set(DAP_SRV_STAKE_SRCS dap_chain_net_srv_stake_lock.c)

file(GLOB DAP_SRV_STAKE_HEADERS include/*.h)

add_library(${PROJECT_NAME} STATIC ${DAP_SRV_STAKE_SRCS} ${DAP_SRV_STAKE_HEADERS})

target_include_directories(${PROJECT_NAME} INTERFACE .)
target_include_directories(${PROJECT_NAME} PUBLIC include)
# All DAP SDK includes are automatically provided through dap_sdk target
target_link_libraries(${PROJECT_NAME} dap_sdk dap_chain dap_chain_ledger dap_chain_net dap_chain_net_srv)

if (INSTALL_SDK)
set_target_properties(${PROJECT_NAME}  PROPERTIES PUBLIC_HEADER "${DAP_SRV_STAKE_HEADERS}")
INSTALL(TARGETS ${PROJECT_NAME} 
        LIBRARY DESTINATION lib/modules/service/stake/
        ARCHIVE DESTINATION lib/modules/service/stake/
        PUBLIC_HEADER DESTINATION include/modules/service/stake/
)
endif()
