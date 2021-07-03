cmake_minimum_required(VERSION 3.0)
project (dap_modules_dynamic_cdb)

file(GLOB DAP_MODULES_DYNAMIC_CDB_SRCS *.c)

file(GLOB DAP_MODULES_DYNAMIC_CDB_HEADERS include/*.h)

add_library(${PROJECT_NAME} STATIC ${DAP_MODULES_DYNAMIC_CDB_SRCS} ${DAP_MODULES_DYNAMIC_CDB_HEADERS})

#target_link_libraries(dap_chain_net_srv dap_core dap_crypto dap_chain dap_chain_net dap_chain_wallet)
target_link_libraries(${PROJECT_NAME} dap_core dap_http_server ${CMAKE_DL_LIBS})

target_include_directories(${PROJECT_NAME} INTERFACE .)
target_include_directories(${PROJECT_NAME} PUBLIC include)
