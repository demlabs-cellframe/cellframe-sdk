# Ledger cache integration tests
#
# Incremental fill + resume of the cached ledger (DAP_LEDGER_CACHE_ENABLED).

cmake_minimum_required(VERSION 3.10)

add_executable(ledger_cache_resume_integration_test
    ledger_cache_resume_integration_test.c
)

target_include_directories(ledger_cache_resume_integration_test PRIVATE
    ${CELLFRAME_TEST_INCLUDES}
    ${CMAKE_CURRENT_SOURCE_DIR}/../../fixtures
)

target_link_libraries(ledger_cache_resume_integration_test
    dap_test
    cellframe_test_fixtures
    cellframe-sdk
)

add_test(NAME ledger_cache_resume COMMAND ledger_cache_resume_integration_test)

set_tests_properties(ledger_cache_resume PROPERTIES
    TIMEOUT 300
    LABELS "integration;ledger;cache"
)
