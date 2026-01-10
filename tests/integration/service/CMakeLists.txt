cmake_minimum_required(VERSION 3.10)
project(stake_ext_integration_tests)

# Stake-ext integration tests
add_executable(${PROJECT_NAME}
    test_stake_ext.c
    main.c
)

# Link modules - includes propagate automatically
target_link_libraries(${PROJECT_NAME}
    dap_test
    dap_sdk
    cellframe_sdk
    test_fixtures
    dap_chain_net_srv_stake_ext  # Stake-ext module
    dap_chain_ledger             # Ledger module
    dap_chain_net                # Net module
)

# Only add local include for our own headers
target_include_directories(${PROJECT_NAME} PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    ${CMAKE_SOURCE_DIR}/tests/fixtures
)

# Add as CTest
add_test(
    NAME stake_ext_integration_tests
    COMMAND ${PROJECT_NAME}
)
