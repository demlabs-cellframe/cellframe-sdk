cmake_minimum_required(VERSION 3.10)
project (dap_stream_ch_chain_net_srv)

# Include LibraryHelpers for object library creation
include(${CMAKE_CURRENT_SOURCE_DIR}/../../../cmake/LibraryHelpers.cmake)

file(GLOB DAP_STREAM_CH_CHAIN_NET_SRV_SRCS *.c)
file(GLOB DAP_STREAM_CH_CHAIN_NET_SRV_HDRS include/*.h)

# Create OBJECT library instead of STATIC
create_object_library(${PROJECT_NAME} CELLFRAME_INTERNAL_MODULES ${DAP_STREAM_CH_CHAIN_NET_SRV_SRCS} HEADERS ${DAP_STREAM_CH_CHAIN_NET_SRV_HDRS})

# Link dependencies as INTERFACE for OBJECT library
# Use dap_link_libraries for automatic include propagation with cycle detection
dap_link_libraries(${PROJECT_NAME} INTERFACE dap_core dap_crypto dap_chain_common dap_chain dap_chain_mempool dap_chain_net dap_chain_net_srv dap_io dap_stream dap_stream_ch dap_stream_ch_chain_net)

target_include_directories(${PROJECT_NAME} INTERFACE .)
target_include_directories(${PROJECT_NAME} PUBLIC include)

if (INSTALL_SDK)
set_target_properties(${PROJECT_NAME}  PROPERTIES PUBLIC_HEADER "${DAP_STREAM_CH_CHAIN_NET_SRV_HDRS}")
INSTALL(TARGETS ${PROJECT_NAME} 
        LIBRARY DESTINATION lib/modules/channel/chain-net-srv/
        ARCHIVE DESTINATION lib/modules/channel/chain-net-srv/
        PUBLIC_HEADER DESTINATION include/modules/channel/chain-net-srv/
)
endif()
