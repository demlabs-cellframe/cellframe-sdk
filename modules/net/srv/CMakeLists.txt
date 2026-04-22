cmake_minimum_required(VERSION 3.13)
project (dap_chain_net_srv)

# Include LibraryHelpers for object library creation
include(${CMAKE_CURRENT_SOURCE_DIR}/../../../cmake/LibraryHelpers.cmake)

file(GLOB DAP_CHAIN_NET_SRV_SRCS *.c)
file(GLOB DAP_CHAIN_NET_SRV_HEADERS include/*.h)

add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/../../../3rdparty/libmaxminddb ${CMAKE_CURRENT_BINARY_DIR}/../../../3rdparty/libmaxminddb)

# Create OBJECT library instead of STATIC
create_object_library(${PROJECT_NAME} CELLFRAME_INTERNAL_MODULES ${DAP_CHAIN_NET_SRV_SRCS} HEADERS ${DAP_CHAIN_NET_SRV_HEADERS})

# Link dependencies as INTERFACE for OBJECT library
# Use dap_link_libraries for automatic include propagation with cycle detection
dap_link_libraries(${PROJECT_NAME} INTERFACE maxminddb dap_core dap_crypto dap_chain dap_chain_net dap_chain_wallet dap_stream_ch_chain_net_srv)

target_include_directories(${PROJECT_NAME} INTERFACE .)
target_include_directories(${PROJECT_NAME} PUBLIC include)
target_include_directories(${PROJECT_NAME} PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/../../../../dap-sdk/3rdparty/uthash/src)

if (INSTALL_SDK)
set_target_properties(${PROJECT_NAME} PROPERTIES PUBLIC_HEADER "${DAP_CHAIN_NET_SRV_HEADERS}")
INSTALL(TARGETS ${PROJECT_NAME} 
        LIBRARY DESTINATION lib/modules/net/srv/
        ARCHIVE DESTINATION lib/modules/net/srv/
        PUBLIC_HEADER DESTINATION include/modules/net/srv/
)
endif()
