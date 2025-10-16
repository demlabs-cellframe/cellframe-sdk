# Test Fixtures Library
# Common utilities and helpers for tests

add_library(cellframe_test_fixtures STATIC
    test_ledger_fixtures.c
    test_token_fixtures.c
    test_transaction_fixtures.c
)

target_link_libraries(cellframe_test_fixtures
    dap_test
    dap_core
    dap_crypto
    dap_chain_common
    dap_chain_cs_dag_poa
    dap_chain_cs_esbocs
)

target_include_directories(cellframe_test_fixtures PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}
)

