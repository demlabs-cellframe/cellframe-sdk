cmake_minimum_required(VERSION 3.10)
project (dap_chain_net_srv_stake_lock)

file(GLOB DAP_SRV_STAKE_LOCK_SRCS *.c)

file(GLOB DAP_SRV_STAKE_LOCK_HEADERS include/*.h)

add_library(${PROJECT_NAME} STATIC ${DAP_SRV_STAKE_LOCK_SRCS} ${DAP_SRV_STAKE_LOCK_HEADERS})

target_include_directories(${PROJECT_NAME} INTERFACE .)
target_include_directories(${PROJECT_NAME} PUBLIC include)
target_include_directories(${PROJECT_NAME} PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/../../../3rdparty/json-c)
target_link_libraries(${PROJECT_NAME} dap_core dap_crypto dap_chain dap_chain_net dap_chain_net_srv)


