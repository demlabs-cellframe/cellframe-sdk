cmake_minimum_required(VERSION 3.10)
project(dap_common)

file(GLOB DAP_COMMON_SRCS *.c)
file(GLOB DAP_COMMON_HEADERS include/*.h)

message("[+] Module 'common' (base types, utilities and RPC callbacks)")
message("[+]   - RPC Callback Registry для Dependency Inversion (Phase 5.3)")
message("[+]   - Network API Layer для Type Extraction (Phase 5.3)")

# Use universal Cellframe library macro
cellframe_add_library(${PROJECT_NAME} ${DAP_COMMON_SRCS})

target_include_directories(${PROJECT_NAME} PUBLIC include)
target_include_directories(${PROJECT_NAME} PUBLIC .)

# Only depends on DAP SDK for basic types + low-level modules for Composer
target_link_libraries(${PROJECT_NAME} 
    dap_core 
    dap_crypto 
    dap_stream 
    dap_global_db 
    dap_link_manager
    dap_chain           # For composer
    dap_chain_datum     # For composer
    dap_chain_ledger    # For composer
)

if(INSTALL_SDK)
    INSTALL(FILES ${DAP_COMMON_HEADERS}
            DESTINATION include/modules/common/
    )
endif()
