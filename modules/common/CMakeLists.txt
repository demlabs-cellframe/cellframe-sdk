cmake_minimum_required(VERSION 3.0)
project (dap_chain_common)
  
file(GLOB DAP_CHAIN_COMMON_SRCS  *.c)
file(GLOB DAP_CHAIN_COMMON_HEADERS include/*.h)

add_library(${PROJECT_NAME} STATIC ${DAP_CHAIN_COMMON_SRCS} ${DAP_CHAIN_COMMON_HEADERS})

target_link_libraries(dap_chain_common dap_core dap_crypto )
target_include_directories(dap_chain_common PUBLIC include/ )
