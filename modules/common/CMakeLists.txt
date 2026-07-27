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

# Only depends on DAP SDK for basic types (dap_link_libraries propagates includes for OBJECT libs)
if(EMSCRIPTEN OR DAP_WASM)
    target_include_directories(${PROJECT_NAME} PRIVATE
        "${CMAKE_SOURCE_DIR}/dap-sdk/module/net/common/include")
    dap_link_libraries(${PROJECT_NAME} INTERFACE dap_core dap_crypto dap_net_common)
else()
    dap_link_libraries(${PROJECT_NAME} INTERFACE dap_core dap_crypto dap_stream dap_global_db dap_link_manager)
endif()

if(INSTALL_SDK)
    INSTALL(FILES ${DAP_COMMON_HEADERS}
            DESTINATION include/modules/common/
    )
endif()
