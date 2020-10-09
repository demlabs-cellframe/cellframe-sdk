cmake_minimum_required(VERSION 3.0)

project(crypto-test)

if ( NOT ( TARGET dap_core ) )
    #add_subdirectory(libdap)
endif()

if ( NOT ( TARGET dap_test ) )
    #add_subdirectory(libdap-test)
endif()

file(GLOB SRC *.h *.c)

add_executable(${PROJECT_NAME} ${SRC})

target_link_libraries(${PROJECT_NAME} dap_test dap_core dap_crypto -lm)

add_test(
    NAME crypto-test
    COMMAND crypto-test
)
