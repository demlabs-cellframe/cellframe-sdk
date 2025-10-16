# Unit Tests for Cellframe SDK

# Example unit test (placeholder)
add_executable(example_test
    example_test.c
)

target_link_libraries(example_test
    dap_test
    cellframe_test_fixtures
    dap_core
    dap_crypto
)

# Register with CTest
add_test(NAME example_test COMMAND example_test)

# UTXO Blocking tests (to be implemented in Phase 3-6)
# Uncomment when ready:
# add_executable(utxo_blocklist_structures_test utxo_blocklist_structures_test.c)
# add_executable(utxo_blocklist_api_test utxo_blocklist_api_test.c)
# add_executable(token_update_utxo_test token_update_utxo_test.c)
# add_executable(ledger_utxo_validation_test ledger_utxo_validation_test.c)
# add_executable(cli_utxo_commands_test cli_utxo_commands_test.c)

