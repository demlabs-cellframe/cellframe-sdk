cmake_minimum_required(VERSION 3.10)
project (dap_chain_net_srv)

file(GLOB DAP_CHAIN_NET_SRV_SRCS *.c)
file(GLOB DAP_CHAIN_NET_SRV_HEADERS *.h include/*.h)
add_library(${PROJECT_NAME} STATIC ${DAP_CHAIN_NET_SRV_SRCS} ${DAP_CHAIN_NET_SRV_HEADERS})

add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/../../3rdparty/libmaxminddb ${CMAKE_CURRENT_BINARY_DIR}/../../3rdparty/libmaxminddb)

target_link_libraries(${PROJECT_NAME} maxminddb dap_core dap_crypto dap_chain dap_chain_net dap_chain_wallet)

target_include_directories(${PROJECT_NAME} INTERFACE .)
target_include_directories(${PROJECT_NAME} PUBLIC include)
target_include_directories(${PROJECT_NAME} PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/../../../../dap-sdk/3rdparty/uthash/src)

if (INSTALL_SDK)
set_target_properties(${PROJECT_NAME}  PROPERTIES PUBLIC_HEADER "${DAP_CHAIN_NET_SRV_HEADERS}")
INSTALL(TARGETS ${PROJECT_NAME}
        LIBRARY DESTINATION lib/modules/net-srv/
        ARCHIVE DESTINATION lib/modules/net-srv/
        PUBLIC_HEADER DESTINATION include/modules/net-srv/
)
endif()
