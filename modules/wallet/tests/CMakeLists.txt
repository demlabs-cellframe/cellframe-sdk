cmake_minimum_required(VERSION 3.10)

# Wallet Cache DB Tests
project(wallet-cache-test)

add_executable(${PROJECT_NAME}
    wallet_cache_test_main.c
    dap_wallet_cache_db_test.c
    include/dap_wallet_cache_db_test.h
)

target_link_libraries(${PROJECT_NAME}
    dap_core
    dap_crypto
    dap_chain
    dap_chain_wallet
    dap_global_db
)

if (DARWIN)
    target_link_libraries(${PROJECT_NAME} bz2)
endif()

target_include_directories(${PROJECT_NAME} PUBLIC include)
target_include_directories(${PROJECT_NAME} PUBLIC ../include)

add_test(
    NAME wallet-cache-test
    COMMAND wallet-cache-test
)

