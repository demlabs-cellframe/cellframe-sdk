if(TARGET chain_crypto_test)
    return() # The project has already been built.
endif()
project(chain_crypto_test)

add_subdirectory(libdap-test)

file(GLOB SOURCES *.c)
file(GLOB HEADERS *.h)

add_executable(${PROJECT_NAME} ${SOURCES} ${HEADERS})

target_link_libraries(${PROJECT_NAME} dap_chain_crypto dap_core dap_crypto dap_chain monero_crypto dap_test)

add_test(
    NAME chain_crypto_test
    COMMAND chain_crypto_test
)
