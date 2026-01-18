cmake_minimum_required(VERSION 3.10)
project(stake_ext_integration_tests)

# Stake-ext integration tests
add_executable(${PROJECT_NAME}
    test_stake_ext.c
    main.c
    $<TARGET_OBJECTS:test_fixtures>
)

# Link modules - includes propagate automatically
target_link_libraries(${PROJECT_NAME}
    dap_test                      # Test framework
    dap_sdk                       # DAP SDK
    cellframe_sdk                 # Cellframe SDK (provides all module headers)
    dap_chain_net_srv_stake_ext   # Stake-ext service module
    dap_chain_ledger              # Ledger module
    dap_chain_net                 # Net module
)

# Only include local test headers - fixtures/modules propagate via OBJECT lib
target_include_directories(${PROJECT_NAME} PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/include
)

# Add as CTest
add_test(
    NAME stake_ext_integration_tests
    COMMAND ${PROJECT_NAME}
)
