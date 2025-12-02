# DEX Integration Tests
# 
# Comprehensive test suite for DEX module covering:
# - Full workflow scenarios (order → purchase → cancel)
# - Multi-component integration (ledger, cache, verifier, matcher)
# - Balance tracking and verification
# - Edge cases and attack prevention
#
# Build: ninja dex_test
# Run: ./tests/integration/dex/dex_test

cmake_minimum_required(VERSION 3.10)

# Integration test executable (modular structure)
add_executable(dex_test
    dex_test_common.c
    dex_test_fixture.c
    dex_test_main.c
    dex_lifecycle_tests.c
    # TODO: add when implemented
    # dex_automatch_tests.c
    # dex_leftover_tests.c
    # dex_operations_tests.c
)

# Include directories
target_include_directories(dex_test PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_SOURCE_DIR}/modules/service/dex/include
    ${CMAKE_SOURCE_DIR}/modules/net/include
    ${CMAKE_SOURCE_DIR}/modules/wallet/include
    ${CMAKE_SOURCE_DIR}/modules/chain/include
    ${CMAKE_SOURCE_DIR}/dap-sdk/core/include
    ${CMAKE_SOURCE_DIR}/dap-sdk/crypto/include
    ${CMAKE_SOURCE_DIR}/tests/include
)

# Link libraries
target_link_libraries(dex_test
    cellframe_test_fixtures
    dap_chain_net_srv_dex
    dap_chain_net
    dap_chain
    dap_chain_common
    dap_chain_wallet
    dap_chain_cs_dag
    dap_chain_cs_dag_poa
    dap_chain_cs_esbocs
    dap_test
    dap_core
    dap_crypto
    pthread
    m
)

# Add test to CTest
add_test(NAME DEX_Integration_Tests COMMAND dex_test)

# Set test properties
set_tests_properties(DEX_Integration_Tests PROPERTIES
    TIMEOUT 300
    LABELS "integration;dex"
)

# Install target (optional)
install(TARGETS dex_test
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}/tests/integration/dex
)

