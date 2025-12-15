cmake_minimum_required(VERSION 3.10)

project(dap_chain_policy)

file(GLOB DAP_CHAIN_POLICY_SRCS *.c)
file(GLOB DAP_CHAIN_POLICY_HEADERS include/*.h)

# Use universal Cellframe library macro
cellframe_add_library(${PROJECT_NAME} ${DAP_CHAIN_POLICY_SRCS} HEADERS ${DAP_CHAIN_POLICY_HEADERS})

# Dependencies:
# - dap_chain_ledger: Use ledger callback registration API
# - dap_chain_net: Call net functions (fee, rewards, etc)
# - dap_chain_cs: Call consensus functions (esbocs, etc)
# - dap_chain_net_srv: Call service functions (stake, etc)
target_link_libraries(${PROJECT_NAME} 
    dap_core 
    dap_chain_ledger
    dap_chain_net
    dap_chain_cs
    dap_chain_net_srv
)

target_include_directories(${PROJECT_NAME} INTERFACE .)
target_include_directories(${PROJECT_NAME} PUBLIC ${CMAKE_SOURCE_DIR}/modules/chain/include)

if (INSTALL_SDK)
set_target_properties(${PROJECT_NAME} PROPERTIES PUBLIC_HEADER "${DAP_CHAIN_POLICY_HEADERS}")
INSTALL(TARGETS ${PROJECT_NAME} 
        LIBRARY DESTINATION lib/modules/policy/
        ARCHIVE DESTINATION lib/modules/policy/
        PUBLIC_HEADER DESTINATION include/modules/policy/
)
endif()



