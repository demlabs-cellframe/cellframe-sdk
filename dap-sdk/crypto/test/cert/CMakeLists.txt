if(TARGET crypto_cert_test)
    return() # The project has already been built.
endif()
project(crypto_cert_test)

file(GLOB SOURCES *.c)
file(GLOB HEADERS *.h)

add_executable(${PROJECT_NAME} ${SOURCES} ${HEADERS})

target_link_libraries(${PROJECT_NAME} dap_crypto dap_core  dap_test)

add_test(
    NAME crypto_cert_test
    COMMAND crypto_cert_test
)
