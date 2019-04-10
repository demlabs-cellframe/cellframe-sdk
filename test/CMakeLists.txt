if(TARGET libdap_client_test)
    return() # The project has already been built.
endif()
project(libdap_client_test)

add_subdirectory(libdap-test)

file(GLOB SOURCES *.c)
file(GLOB HEADERS *.h)

add_executable(${PROJECT_NAME} ${SOURCES} ${HEADERS})

target_link_libraries(${PROJECT_NAME} dap_test dap_core)

add_test(
    NAME libdap_client_test
    COMMAND libdap_client_test
)
