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

# UTXO Blocking Unit Tests
add_executable(utxo_blocking_unit_test
    utxo_blocking_unit_test.c
)

target_link_libraries(utxo_blocking_unit_test
    dap_test
    dap_core
    dap_chain
    dap_chain_net
    dap_crypto
)

target_include_directories(utxo_blocking_unit_test PRIVATE
    ${CMAKE_SOURCE_DIR}/modules/common/include
    ${CMAKE_SOURCE_DIR}/modules/net/include
    ${CMAKE_SOURCE_DIR}/3rdparty/uthash/src
)

# Register with CTest
add_test(NAME utxo_blocking_unit COMMAND utxo_blocking_unit_test)

# Set test properties
set_tests_properties(utxo_blocking_unit PROPERTIES
    TIMEOUT 60
    LABELS "unit;utxo;blocking"
)

message(STATUS "Unit tests configured: utxo_blocking_unit_test")
