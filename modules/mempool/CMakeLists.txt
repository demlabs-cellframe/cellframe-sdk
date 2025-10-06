cmake_minimum_required(VERSION 3.10)
project (dap_chain_mempool)

file(GLOB DAP_CHAIN_MEMPOOL_SRC *.c)
file(GLOB DAP_CHAIN_MEMPOOL_HDR include/*.h)

cellframe_add_library(${PROJECT_NAME} ${DAP_CHAIN_MEMPOOL_SRC} HEADERS ${DAP_CHAIN_MEMPOOL_HDR})

target_link_libraries(${PROJECT_NAME} dap_http_server dap_client dap_chain_net dap_global_db dap_core dap_json_rpc dap_chain_ledger dap_compose)
target_include_directories(${PROJECT_NAME} INTERFACE .)
target_include_directories(${PROJECT_NAME} PUBLIC include)

if (INSTALL_SDK)
set_target_properties(${PROJECT_NAME}  PROPERTIES PUBLIC_HEADER "${DAP_CHAIN_MEMPOOL_HDR}")
INSTALL(TARGETS ${PROJECT_NAME} 
        LIBRARY DESTINATION lib/modules/mempool/
        ARCHIVE DESTINATION lib/modules/mempool/
        PUBLIC_HEADER DESTINATION include/modules/mempool/
        )
endif()