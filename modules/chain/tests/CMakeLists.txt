cmake_minimum_required(VERSION 3.10)

# Main chain tests (ledger)
project(chain-test)

file(GLOB DAP_CHAIN_TESTS_HEADERS include/*.h)
file(GLOB DAP_CHAIN_TESTS_SRC 
    main.c 
    dap_chain_ledger_tests.c
)

add_executable(${PROJECT_NAME} ${DAP_CHAIN_TESTS_SRC} ${DAP_CHAIN_TESTS_HEADERS})

target_link_libraries(${PROJECT_NAME} dap_test dap_sdk cellframe_sdk)

if (DARWIN)
    target_link_libraries(${PROJECT_NAME} bz2)
endif()

target_include_directories(${PROJECT_NAME} PUBLIC include)

add_test(
    NAME chain-test
    COMMAND chain-test
)

# Chain Cell Read/Write Tests
project(chain-cell-test)

add_executable(${PROJECT_NAME}
    chain_cell_test_main.c
    dap_chain_cell_test.c
    include/dap_chain_cell_test.h
)

target_link_libraries(${PROJECT_NAME} 
    dap_test 
    dap_core 
    dap_crypto 
    dap_chain
    dap_chain_datum
    dap_chain_net
    dap_chain_wallet
    dap_chain_mempool
    dap_chain_ledger
    dap_chain_net_srv
    dap_chain_cs_blocks
    dap_chain_cs_esbocs
    dap_chain_net_srv_stake
    dap_chain_node_cli
)

if (DARWIN)
    target_link_libraries(${PROJECT_NAME} bz2)
endif()

target_include_directories(${PROJECT_NAME} PUBLIC include)

add_test(
    NAME chain-cell-test
    COMMAND chain-cell-test
)
