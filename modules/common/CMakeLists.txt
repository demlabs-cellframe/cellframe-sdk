cmake_minimum_required(VERSION 3.10)
project (dap_chain_common)
  
file(GLOB DAP_CHAIN_COMMON_SRCS  *.c)
file(GLOB DAP_CHAIN_COMMON_HEADERS include/*.h)

add_library(${PROJECT_NAME} STATIC ${DAP_CHAIN_COMMON_SRCS} ${DAP_CHAIN_COMMON_HEADERS})

target_link_libraries(${PROJECT_NAME} dap_core dap_crypto )
target_include_directories(${PROJECT_NAME} PUBLIC include/ )
