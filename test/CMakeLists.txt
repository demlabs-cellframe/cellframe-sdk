if(TARGET core_server_test)
    return() # The project has already been built.
endif()
project(core_server_test)

add_subdirectory(libdap-test)

file(GLOB SOURCES *.c)
file(GLOB HEADERS *.h)

add_executable(${PROJECT_NAME} ${SOURCES} ${HEADERS})

target_link_libraries(${PROJECT_NAME} dap_test dap_core_server ev)

add_test(
    NAME core_server_test
    COMMAND core_server_test
)
