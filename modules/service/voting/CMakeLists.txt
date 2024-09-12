cmake_minimum_required(VERSION 3.10)
project (dap_chain_net_srv_voting)

file(GLOB DAP_SRV_VTNG_SRCS *.c)

file(GLOB DAP_SRV_VTNG_HEADERS include/*.h)

add_library(${PROJECT_NAME} STATIC ${DAP_SRV_VTNG_SRCS} ${DAP_SRV_VTNG_HEADERS})

target_include_directories(${PROJECT_NAME} INTERFACE .)
target_include_directories(${PROJECT_NAME} PUBLIC include)
target_link_libraries(${PROJECT_NAME} dap_core dap_crypto dap_chain dap_chain_net dap_chain_net_srv)
target_include_directories(${PROJECT_NAME} PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/../../../../dap-sdk/3rdparty/json-c)

if (INSTALL_SDK)
set_target_properties(${PROJECT_NAME}  PROPERTIES PUBLIC_HEADER "${DAP_SRV_BRG_HEADERS}")
INSTALL(TARGETS ${PROJECT_NAME} 
        LIBRARY DESTINATION lib/modules/service/voting/
        ARCHIVE DESTINATION lib/modules/service/voting/
        PUBLIC_HEADER DESTINATION include/modules/service/voting/
)
endif()