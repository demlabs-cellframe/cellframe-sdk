project (dap_chain_bridge_btc)
  
file(GLOB DAP_CHAIN_BRIDGE_BTC_SRCS *.c)

file(GLOB DAP_CHAIN_BRIDGE_BTC_HEADERS include/*.h)

add_library(${PROJECT_NAME} STATIC ${DAP_CHAIN_BRIDGE_BTC_SRCS} ${DAP_CHAIN_BRIDGE_BTC_HEADERS})

target_include_directories(dap_chain_crypto INTERFACE .)
target_include_directories(${PROJECT_NAME} PUBLIC include)
target_link_libraries(${PROJECT_NAME} dap_core dap_crypto dap_chain dap_chain_crypto dap_chain_net )

#INSTALL(DIRECTORY ${ share/ DESTINATION ${CMAKE_INSTALL_PREFIX}/share/bridge-btc/ FILES_MATCHING PATTERN "*"  PATTERN "*")
