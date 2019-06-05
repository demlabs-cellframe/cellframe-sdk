project(dap_client_test)


if ( NOT ( TARGET dap_test ) )
    add_subdirectory(libdap-test)
endif()

file(GLOB DAP_CLIENT_TEST_SOURCES *.c)
file(GLOB DAP_CLIENT_TEST_HEADERS *.h)

add_executable(${PROJECT_NAME} ${DAP_CLIENT_TEST_SOURCES} ${DAP_CLIENT_TEST_HEADERS})

target_link_libraries(${PROJECT_NAME} dap_test dap_core dap_crypto dap_server_core ev pthread)

add_test(
    NAME dap_client_test
    COMMAND dap_client_test
)
