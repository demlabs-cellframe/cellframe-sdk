cmake_minimum_required(VERSION 2.8)
project (dap_app_cli)
  
set(DAP_APP_CLI_SRCS
        src/dap_app_cli.c
        src/dap_app_cli_net.c
        src/dap_app_cli_shell.c
        )

set(DAP_APP_CLI_HEADERS
        include/dap_app_cli.h
        include/dap_app_cli_net.h
        include/dap_app_cli_shell.h
    )


if(WIN32)
  #include_directories(../3rdparty/curl/include/)
endif()

add_library(${PROJECT_NAME} STATIC ${DAP_APP_CLI_SRCS} ${DAP_APP_CLI_HEADERS} )

target_link_libraries(${PROJECT_NAME} dap_core dap_chain_net m curl)
target_include_directories(${PROJECT_NAME} PUBLIC include/ )
