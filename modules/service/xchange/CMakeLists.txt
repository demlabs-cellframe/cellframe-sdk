cmake_minimum_required(VERSION 3.10)
project (dap_chain_net_srv_xchange)
  
file(GLOB DAP_SRV_XCHANGE_SRCS *.c)

file(GLOB DAP_SRV_XCHANGE_HEADERS include/*.h)

add_library(${PROJECT_NAME} STATIC ${DAP_SRV_XCHANGE_SRCS} ${DAP_SRV_XCHANGE_HEADERS})

target_include_directories(${PROJECT_NAME} INTERFACE .)
target_include_directories(${PROJECT_NAME} PUBLIC include)
target_link_libraries(${PROJECT_NAME} dap_core dap_crypto dap_chain dap_chain_net dap_chain_net_srv)

if (INSTALL_SDK)
set_target_properties(${PROJECT_NAME}  PROPERTIES PUBLIC_HEADER "${DAP_SRV_XCHANGE_HEADERS}")
INSTALL(TARGETS ${PROJECT_NAME} 
        LIBRARY DESTINATION lib/modules/service/xchange/
        ARCHIVE DESTINATION lib/modules/service/xchange/
        PUBLIC_HEADER DESTINATION include/modules/service/xchange/
)
endif()