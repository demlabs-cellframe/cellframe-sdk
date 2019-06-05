if(TARGET server_core_test)
    return() # The project has already been built.
endif()
project(server_core_test)

add_subdirectory(libdap-test)

file(GLOB SOURCES *.c)
file(GLOB HEADERS *.h)

add_executable(${PROJECT_NAME} ${SOURCES} ${HEADERS})

target_link_libraries(${PROJECT_NAME} dap_test dap_core dap_crypto dap_server_core ev)

add_test(
    NAME core_server_test
    COMMAND core_server_test
)
