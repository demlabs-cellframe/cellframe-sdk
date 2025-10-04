cmake_minimum_required(VERSION 3.10)
project (dap_chain_net_srv_voting)

file(GLOB DAP_SRV_VTNG_SRCS *.c)

file(GLOB DAP_SRV_VTNG_HEADERS include/*.h)

cellframe_add_library(${PROJECT_NAME} ${DAP_SRV_VTNG_SRCS} HEADERS ${DAP_SRV_VTNG_HEADERS})

target_include_directories(${PROJECT_NAME} INTERFACE .)
target_include_directories(${PROJECT_NAME} PUBLIC include)
target_link_libraries(${PROJECT_NAME} dap_sdk dap_chain dap_chain_net dap_chain_net_srv dap_chain_node_cli dap_compose)

if (INSTALL_SDK)
set_target_properties(${PROJECT_NAME}  PROPERTIES PUBLIC_HEADER "${DAP_SRV_BRG_HEADERS}")
INSTALL(TARGETS ${PROJECT_NAME} 
        LIBRARY DESTINATION lib/modules/service/voting/
        ARCHIVE DESTINATION lib/modules/service/voting/
        PUBLIC_HEADER DESTINATION include/modules/service/voting/
)
endif()