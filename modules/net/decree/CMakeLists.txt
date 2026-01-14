file(GLOB DAP_CHAIN_NET_DECREE_SRCS *.c)
file(GLOB DAP_CHAIN_NET_DECREE_HDRS *.h)

add_library(dap_chain_net_decree STATIC ${DAP_CHAIN_NET_DECREE_SRCS} ${DAP_CHAIN_NET_DECREE_HDRS})

target_link_libraries(dap_chain_net_decree PRIVATE
    dap_core
    dap_chain_governance
    dap_chain_ledger
)

target_include_directories(dap_chain_net_decree PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}/../include
)

