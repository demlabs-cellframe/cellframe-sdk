# Unit tests for dap_chain_datum module

# Test for transaction JSON serialization
add_executable(test_dap_chain_datum_tx_json
    test_dap_chain_datum_tx_son.c
)

target_link_libraries(test_dap_chain_datum_tx_json
    dap_chain_datum
    dap_chain_net
    dap_chain_common
    dap_common
    dap_enc
    dap_sign
    dap_time
    json-c
)

# Add test to CTest
add_test(NAME test_dap_chain_datum_tx_json COMMAND test_dap_chain_datum_tx_json) 