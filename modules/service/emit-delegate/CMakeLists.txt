cmake_minimum_required(VERSION 3.10)
project (dap_chain_net_srv_emit_delegate)

file(GLOB DAP_CHAIN_NET_SRV_EMIT_SRCS *.c)

file(GLOB DAP_CHAIN_NET_SRV_EMIT_HDRS include/*.h)

add_library(${PROJECT_NAME} STATIC ${DAP_CHAIN_NET_SRV_EMIT_SRCS} ${DAP_CHAIN_NET_SRV_EMIT_HDRS})

target_include_directories(${PROJECT_NAME} INTERFACE .)
target_include_directories(${PROJECT_NAME} PUBLIC include)
target_link_libraries(${PROJECT_NAME} dap_core dap_crypto dap_chain dap_chain_net dap_chain_net_srv)

if (INSTALL_SDK)
set_target_properties(${PROJECT_NAME}  PROPERTIES PUBLIC_HEADER "${DAP_CHAIN_NET_SRV_EMIT_HDRS}")
INSTALL(TARGETS ${PROJECT_NAME} 
        LIBRARY DESTINATION lib/modules/service/emit-delegate/
        ARCHIVE DESTINATION lib/modules/service/emit-delegate/
        PUBLIC_HEADER DESTINATION include/modules/service/emit-delegate/
)
endif()
