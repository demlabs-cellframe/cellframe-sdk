cmake_minimum_required(VERSION 3.10)
project (dap_chain_net_srv_auctions)

file(GLOB DAP_SRV_AUCTIONS_SRCS *.c)

file(GLOB DAP_SRV_AUCTIONS_HEADERS include/*.h)

cellframe_add_library(${PROJECT_NAME} ${DAP_SRV_AUCTIONS_SRCS} HEADERS ${DAP_SRV_AUCTIONS_HEADERS})

target_include_directories(${PROJECT_NAME} INTERFACE .)
target_include_directories(${PROJECT_NAME} PUBLIC include)
target_link_libraries(${PROJECT_NAME} dap_core dap_crypto dap_chain dap_chain_net dap_chain_net_srv)
target_include_directories(${PROJECT_NAME} PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/../../../../dap-sdk/3rdparty/json-c)

if(BUILD_CELLFRAME_SDK_TESTS)
    add_definitions("-DDAP_AUCTIONS_TEST")
    add_subdirectory(tests)
endif()

if (INSTALL_SDK)
set_target_properties(${PROJECT_NAME}  PROPERTIES PUBLIC_HEADER "${DAP_SRV_AUCTIONS_HEADERS}")
INSTALL(TARGETS ${PROJECT_NAME} 
        LIBRARY DESTINATION lib/modules/service/auctions/
        ARCHIVE DESTINATION lib/modules/service/auctions/
        PUBLIC_HEADER DESTINATION include/modules/service/auctions/
)
endif()