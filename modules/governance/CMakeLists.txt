cmake_minimum_required(VERSION 3.10)

project(dap_chain_governance)

file(GLOB DAP_CHAIN_GOVERNANCE_SRCS *.c)
file(GLOB DAP_CHAIN_GOVERNANCE_HEADERS include/*.h)

# Governance module - high-level management (decrees, policies, etc)
cellframe_add_library(${PROJECT_NAME} ${DAP_CHAIN_GOVERNANCE_SRCS} HEADERS ${DAP_CHAIN_GOVERNANCE_HEADERS})

# Governance is HIGH-LEVEL module - CAN depend on net, stake, etc
target_link_libraries(${PROJECT_NAME}
    dap_core
    dap_crypto
    dap_chain
    dap_chain_datum
    dap_chain_ledger
    dap_chain_net
    dap_chain_net_tx
    dap_global_db
    dap_http_server
)

target_include_directories(${PROJECT_NAME} INTERFACE .)
target_include_directories(${PROJECT_NAME} PUBLIC include)

if(INSTALL_SDK)
    set_target_properties(${PROJECT_NAME} PROPERTIES PUBLIC_HEADER "${DAP_CHAIN_GOVERNANCE_HEADERS}")
    INSTALL(TARGETS ${PROJECT_NAME}
        LIBRARY DESTINATION lib/modules/governance/
        ARCHIVE DESTINATION lib/modules/governance/
        PUBLIC_HEADER DESTINATION include/modules/governance/
    )
endif()


