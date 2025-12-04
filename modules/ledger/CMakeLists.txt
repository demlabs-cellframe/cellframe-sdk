cmake_minimum_required(VERSION 3.10)

project (dap_chain_ledger)

file(GLOB DAP_CHAIN_LEDGER_SRCS *.c)
file(GLOB DAP_CHAIN_LEDGER_HEADERS include/*.h)

# Use universal Cellframe library macro
cellframe_add_library(${PROJECT_NAME} ${DAP_CHAIN_LEDGER_SRCS} HEADERS ${DAP_CHAIN_LEDGER_HEADERS})

target_link_libraries(${PROJECT_NAME} dap_core dap_crypto dap_notify_srv dap_chain dap_global_db dap_json_rpc dap_common)
target_include_directories(${PROJECT_NAME} INTERFACE . )
target_include_directories(${PROJECT_NAME} PUBLIC include)
target_include_directories(${PROJECT_NAME} PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/../../../dap-sdk/3rdparty/uthash/src)

# Add tests subdirectory if testing is enabled
if(BUILD_CELLFRAME_SDK_TESTS)
    message("[+] Adding ledger tests subdirectory")
    add_subdirectory(tests)
else()
    message("[-] Ledger tests disabled (BUILD_CELLFRAME_SDK_TESTS=${BUILD_CELLFRAME_SDK_TESTS})")
endif()

if (INSTALL_SDK)
set_target_properties(${PROJECT_NAME}  PROPERTIES PUBLIC_HEADER "${DAP_CHAIN_LEDGER_HEADERS}")
INSTALL(TARGETS ${PROJECT_NAME} 
        LIBRARY DESTINATION lib/modules/ledger/
        ARCHIVE DESTINATION lib/modules/ledger/
        PUBLIC_HEADER DESTINATION include/modules/ledger/
)
endif() 
