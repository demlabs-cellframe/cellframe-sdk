project(server_core_test)

if ( NOT ( TARGET dap_test ) )
    add_subdirectory(libdap-test)
endif()

file(GLOB DAP_SERVER_CORE_TEST_SOURCES *.c)
file(GLOB DAP_SERVER_CORE_TEST_HEADERS *.h)

add_executable(${PROJECT_NAME} ${DAP_SERVER_CORE_TEST_SOURCES} ${DAP_SERVER_CORE_TEST_HEADERS})

target_link_libraries(${PROJECT_NAME} dap_test dap_core dap_crypto dap_server_core ev)

add_test(
    NAME server_core_test
    COMMAND server_core_test
)
