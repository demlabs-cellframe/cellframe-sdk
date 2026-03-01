cmake_minimum_required(VERSION 3.10)

project(test_ledger_tx_operations)

# Include DAP Mock AutoWrap module
include(${CMAKE_SOURCE_DIR}/dap-sdk/module/test/mocks/DAPMockAutoWrap.cmake)

add_executable(${PROJECT_NAME}
    test_ledger_tx_operations.c
)

# No explicit includes needed - all propagate via linked modules

# Link modules - includes propagate automatically
target_link_libraries(${PROJECT_NAME}
    dap_test          # Test framework
    dap_sdk           # DAP SDK
    cellframe_sdk     # Cellframe SDK (provides ledger/chain headers)
    dap_chain_ledger  # Ledger module (for implementation, headers from cellframe_sdk)
)

# Set additional includes for custom mock generation
set(ENV{DAP_MOCK_ADDITIONAL_INCLUDES} "#include \"dap_hash.h\"\n#include \"dap_chain_common.h\"\n#include \"dap_chain_datum.h\"\n#include \"dap_chain_datum_tx.h\"\n#include \"dap_chain_ledger.h\"")

# Auto-generate and apply --wrap flags from DAP_MOCK_DECLARE() and DAP_MOCK_CUSTOM() calls
dap_mock_autowrap(${PROJECT_NAME})

add_test(NAME ${PROJECT_NAME} COMMAND ${PROJECT_NAME})

# --- Ledger Cache Tests ---
set(CACHE_TEST_NAME test_ledger_cache)

add_executable(${CACHE_TEST_NAME}
    test_ledger_cache.c
)

target_link_libraries(${CACHE_TEST_NAME}
    dap_test
    dap_sdk
    cellframe_sdk
    dap_chain_ledger
)

add_test(NAME ${CACHE_TEST_NAME} COMMAND ${CACHE_TEST_NAME})

# --- Ledger Cache Performance Benchmark ---
set(CACHE_BENCH_NAME bench_ledger_cache)

add_executable(${CACHE_BENCH_NAME}
    bench_ledger_cache.c
)

target_link_libraries(${CACHE_BENCH_NAME}
    dap_test
    dap_sdk
    cellframe_sdk
    dap_chain_ledger
)

add_test(NAME ${CACHE_BENCH_NAME} COMMAND ${CACHE_BENCH_NAME})
