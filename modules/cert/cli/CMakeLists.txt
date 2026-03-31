cmake_minimum_required(VERSION 3.10)
project(dap_cert_cli)

file(GLOB DAP_CERT_CLI_SRCS *.c)
file(GLOB DAP_CERT_CLI_HEADERS *.h)

cellframe_add_library(${PROJECT_NAME} ${DAP_CERT_CLI_SRCS} HEADERS ${DAP_CERT_CLI_HEADERS})

target_link_libraries(${PROJECT_NAME} 
    dap_core 
    dap_crypto         
    dap_cli_server)

target_include_directories(${PROJECT_NAME} INTERFACE .)
target_include_directories(${PROJECT_NAME} PUBLIC .)

if (INSTALL_SDK)
set_target_properties(${PROJECT_NAME} PROPERTIES PUBLIC_HEADER "${DAP_CERT_CLI_HEADERS}")
INSTALL(TARGETS ${PROJECT_NAME} 
        LIBRARY DESTINATION lib/modules/cert/cli/
        ARCHIVE DESTINATION lib/modules/cert/cli/
        PUBLIC_HEADER DESTINATION include/modules/cert/cli/
)
endif()
