cmake_minimum_required(VERSION 3.10)
project (dap_chain_wallet)

file(GLOB DAP_CHAIN_WALLET_SRCS *.c)
file(GLOB DAP_CHAIN_WALLET_HEADERS include/*.h)

add_library(${PROJECT_NAME} STATIC ${DAP_CHAIN_WALLET_SRCS} ${DAP_CHAIN_WALLET_HEADERS})

target_link_libraries(${PROJECT_NAME} dap_core dap_crypto dap_chain dap_chain_net crc32c_adler)
if (DAP_SDK_STANDALONE_BUILD)
    target_include_directories(${PROJECT_NAME} PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/../../dap-sdk/3rdparty/crc32c_adler)
else()
    target_include_directories(${PROJECT_NAME} PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/../../../dap-sdk/3rdparty/crc32c_adler)
endif()
target_include_directories(${PROJECT_NAME} INTERFACE .)
target_include_directories(${PROJECT_NAME} PUBLIC include)
