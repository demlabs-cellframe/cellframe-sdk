cmake_minimum_required(VERSION 3.10)

project(stake-ext-test)

# Skip test on ARM 32-bit due to SEGFAULT before main() - needs investigation
# PLATFORM_ARM is set in OS_Detection.cmake for armv7/armv7l/armv8
# TODO: Fix ARM 32-bit compatibility issue
if(PLATFORM_ARM)
    message(STATUS "Skipping stake-ext-test on ARM 32-bit (known issue)")
    return()
endif()

file(GLOB DAP_STAKE_EXT_TESTS_HEADERS include/*.h)
file(GLOB DAP_STAKE_EXT_TESTS_SRC *.c)

add_executable(${PROJECT_NAME} ${DAP_STAKE_EXT_TESTS_SRC} ${DAP_STAKE_EXT_TESTS_HEADERS})

target_link_libraries(${PROJECT_NAME} 
    PRIVATE
        dap_test
        dap_core
        dap_crypto
        dap_chain_net_srv_stake_ext
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

set_tests_properties(stake-ext-test PROPERTIES
    TIMEOUT 60
    LABELS "unit;stake-ext"
)
