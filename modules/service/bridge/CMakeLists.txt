cmake_minimum_required(VERSION 3.10)
project (dap_chain_net_srv_bridge)

file(GLOB DAP_SRV_BRG_SRCS *.c)

file(GLOB DAP_SRV_BRG_HEADERS include/*.h)

add_library(${PROJECT_NAME} STATIC ${DAP_SRV_BRG_SRCS} ${DAP_SRV_BRG_HEADERS})

target_include_directories(${PROJECT_NAME} INTERFACE .)
target_include_directories(${PROJECT_NAME} PUBLIC include)
target_link_libraries(${PROJECT_NAME} dap_core dap_crypto dap_chain dap_chain_net dap_chain_net_srv)
target_include_directories(${PROJECT_NAME} PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/../../../../dap-sdk/3rdparty/json-c)

if (INSTALL_SDK)
set_target_properties(${PROJECT_NAME}  PROPERTIES PUBLIC_HEADER "${DAP_SRV_BRG_HEADERS}")
INSTALL(TARGETS ${PROJECT_NAME} 
        LIBRARY DESTINATION lib/modules/service/bridge/
        ARCHIVE DESTINATION lib/modules/service/bridge/
        PUBLIC_HEADER DESTINATION include/modules/service/bridge/
)
endif()