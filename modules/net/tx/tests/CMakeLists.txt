cmake_minimum_required(VERSION 3.10)
project(tx_compose_tests C)

# TX Compose unit tests
add_executable(tx-compose-test
    dap_chain_tx_compose_test.c
)

target_link_libraries(tx-compose-test
    dap_test
    dap_core
    dap_chain_net_tx
    dap_chain_ledger
    dap_chain_datum
    dap_chain_utxo
)

target_include_directories(tx-compose-test PRIVATE
    ../../../dap-sdk/module/test/include
    ../../../dap-sdk/module/core/include
    ../include
    ../../ledger/include
    ../../datum/include
    ../../utxo/include
)

# Add test to CTest
add_test(NAME tx_compose_unit COMMAND tx-compose-test)
set_tests_properties(tx_compose_unit PROPERTIES
    LABELS "unit;tx;compose"
)
