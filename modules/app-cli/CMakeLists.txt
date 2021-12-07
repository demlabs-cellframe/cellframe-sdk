cmake_minimum_required(VERSION 3.10)
project (dap_app_cli)

file(GLOB DAP_APP_CLI_SRCS *.c)

file(GLOB DAP_APP_CLI_HEADERS include/*.h)

add_library(${PROJECT_NAME} STATIC ${DAP_APP_CLI_SRCS} ${DAP_APP_CLI_HEADERS} )

target_link_libraries(${PROJECT_NAME} dap_core dap_chain_net m)
target_include_directories(${PROJECT_NAME} PUBLIC include/ )
