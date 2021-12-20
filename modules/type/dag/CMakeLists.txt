cmake_minimum_required(VERSION 3.10)
project (dap_chain_cs_dag)
  
file(GLOB DAP_CHAIN_DAG_SRCS *.c)
file(GLOB DAP_CHAIN_DAG_HEADERS include/*.h)
add_library(${PROJECT_NAME} STATIC ${DAP_CHAIN_DAG_SRCS} ${DAP_CHAIN_DAG_HEADERS})

target_link_libraries(${PROJECT_NAME} dap_core dap_crypto dap_chain dap_chain_net dap_chain_global_db)
target_include_directories(${PROJECT_NAME} INTERFACE .)
target_include_directories(${PROJECT_NAME} PUBLIC include)
target_include_directories(${PROJECT_NAME} PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/../../../3rdparty/uthash/src)
