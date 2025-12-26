cmake_minimum_required(VERSION 3.10)

project(stake-ext-test)

file(GLOB DAP_STAKE_EXT_TESTS_HEADERS include/*.h)
file(GLOB DAP_STAKE_EXT_TESTS_SRC *.c)

add_executable(${PROJECT_NAME} ${DAP_STAKE_EXT_TESTS_SRC} ${DAP_STAKE_EXT_TESTS_HEADERS})

target_link_libraries(${PROJECT_NAME} 
    dap_test 
    dap_core 
    dap_crypto 
    dap_chain 
    dap_chain_net 
    dap_chain_net_srv 
    dap_chain_net_srv_stake_ext
    dap_chain_wallet
)

if (DARWIN)
    target_link_libraries(${PROJECT_NAME} bz2)
endif()

target_include_directories(${PROJECT_NAME} PUBLIC include)
target_include_directories(${PROJECT_NAME} PUBLIC ../include)

add_test(
    NAME stake-ext-test
    COMMAND stake-ext-test
)
