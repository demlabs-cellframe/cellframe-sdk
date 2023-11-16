cmake_minimum_required(VERSION 3.10)
project (dap_chain_wallet)

file(GLOB DAP_CHAIN_WALLET_SRCS *.c)
file(GLOB DAP_CHAIN_WALLET_HEADERS include/*.h)

add_library(${PROJECT_NAME} STATIC ${DAP_CHAIN_WALLET_SRCS} ${DAP_CHAIN_WALLET_HEADERS})

target_link_libraries(${PROJECT_NAME} dap_core dap_crypto dap_chain dap_chain_net crc32c_adler)

target_include_directories(${PROJECT_NAME} INTERFACE .)
target_include_directories(${PROJECT_NAME} PUBLIC include)

if (INSTALL_SDK)
set_target_properties(${PROJECT_NAME}  PROPERTIES PUBLIC_HEADER "${DAP_CHAIN_WALLET_HEADERS}")
INSTALL(TARGETS ${PROJECT_NAME} 
        LIBRARY DESTINATION lib/modules/wallet/
        ARCHIVE DESTINATION lib/modules/wallet/
        PUBLIC_HEADER DESTINATION include/modules/wallet/
)
endif()