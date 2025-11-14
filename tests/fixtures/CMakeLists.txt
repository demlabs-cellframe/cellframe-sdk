# Test Fixtures Library
# Common utilities and helpers for tests

add_library(cellframe_test_fixtures STATIC
    test_ledger_fixtures.c
    test_token_fixtures.c
    test_transaction_fixtures.c
    test_emission_fixtures.c
)

target_link_libraries(cellframe_test_fixtures
    dap_test
    dap_core
    dap_crypto
    dap_chain_common
)

target_include_directories(cellframe_test_fixtures PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}/../../modules/common/include
)

# Add GlobalDB driver defines to fixtures (same as global-db library)
if(BUILD_WITH_GDB_DRIVER_MDBX)
    target_compile_definitions(cellframe_test_fixtures PRIVATE DAP_CHAIN_GDB_ENGINE_MDBX)
endif()
if(BUILD_WITH_GDB_DRIVER_PGSQL)
    target_compile_definitions(cellframe_test_fixtures PRIVATE DAP_CHAIN_GDB_ENGINE_PGSQL)
endif()
if(BUILD_WITH_GDB_DRIVER_SQLITE)
    target_compile_definitions(cellframe_test_fixtures PRIVATE DAP_CHAIN_GDB_ENGINE_SQLITE)
endif()

