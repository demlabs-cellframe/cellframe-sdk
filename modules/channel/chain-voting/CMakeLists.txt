cmake_minimum_required(VERSION 3.10)
project (dap_stream_ch_chain_voting)
  
file(GLOB DAP_STREAM_CH_CHAIN_VOTING_SRCS *.c)
file(GLOB DAP_STREAM_CH_CHAIN_VOTING_HDRS include/*.h)

add_library(${PROJECT_NAME} STATIC ${DAP_STREAM_CH_CHAIN_VOTING_SRCS} ${DAP_STREAM_CH_CHAIN_VOTING_HDRS})

target_link_libraries(${PROJECT_NAME} dap_core dap_crypto dap_stream dap_stream_ch dap_chain_net)


target_include_directories(${PROJECT_NAME} INTERFACE .)
target_include_directories(${PROJECT_NAME} PUBLIC include)
target_include_directories(${PROJECT_NAME} PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/../../../../dap-sdk/3rdparty/uthash/src)

if (INSTALL_SDK)
set_target_properties(${PROJECT_NAME}  PROPERTIES PUBLIC_HEADER "${DAP_STREAM_CH_CHAIN_VOTING_HDRS}")
INSTALL(TARGETS ${PROJECT_NAME} 
        LIBRARY DESTINATION lib/modules/channel/chain-voting/
        ARCHIVE DESTINATION lib/modules/channel/chain-voting/
        PUBLIC_HEADER DESTINATION include/modules/channel/chain-voting/
)
endif()