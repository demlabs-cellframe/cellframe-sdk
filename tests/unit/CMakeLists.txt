# Unit Tests for Cellframe SDK

# UTXO Blocking Unit Tests
add_executable(utxo_blocking_unit_test
    utxo_blocking_unit_test.c
)

target_include_directories(utxo_blocking_unit_test PRIVATE 
    ${CELLFRAME_TEST_INCLUDES}
)

target_link_libraries(utxo_blocking_unit_test
    dap_test
    dap_core
    dap_crypto
    dap_chain_common
)

# Register with CTest
add_test(NAME utxo_blocking_unit COMMAND utxo_blocking_unit_test)

# Set test properties
set_tests_properties(utxo_blocking_unit PROPERTIES
    TIMEOUT 30
    LABELS "unit;utxo;blocking"
)

message(STATUS "Unit tests configured: utxo_blocking_unit_test")
