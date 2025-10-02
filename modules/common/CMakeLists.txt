cmake_minimum_required(VERSION 3.10)
project(dap_common)

file(GLOB DAP_COMMON_SRCS *.c)
file(GLOB DAP_COMMON_HEADERS include/*.h)

message("[+] Module 'common' (base types and utilities)")

# Use universal Cellframe library macro
cellframe_add_library(${PROJECT_NAME} ${DAP_COMMON_SRCS} HEADERS ${DAP_COMMON_HEADERS})

target_include_directories(${PROJECT_NAME} PUBLIC include)
target_include_directories(${PROJECT_NAME} PUBLIC .)

# Only depends on DAP SDK for basic types
# NO PRIVATE includes - решаем через правильную архитектуру!
target_link_libraries(${PROJECT_NAME} dap_core dap_crypto dap_stream dap_global_db dap_chain dap_chain_datum)

if(INSTALL_SDK)
    INSTALL(FILES ${DAP_COMMON_HEADERS}
            DESTINATION include/modules/common/
    )
endif()
