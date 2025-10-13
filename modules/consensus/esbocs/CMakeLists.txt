cmake_minimum_required(VERSION 3.10)
project (dap_chain_cs_esbocs)
  
file(GLOB DAP_CHAIN_ESBOCS_SRCS *.c)
file(GLOB DAP_CHAIN_CS_ESBOCS_HEADERS include/*.h)

# Use universal Cellframe library macro
cellframe_add_library(${PROJECT_NAME} ${DAP_CHAIN_ESBOCS_SRCS} HEADERS ${DAP_CHAIN_CS_ESBOCS_HEADERS})

target_include_directories(${PROJECT_NAME} INTERFACE .)
target_include_directories(${PROJECT_NAME} PUBLIC include)

# Add DAP SDK include directories
target_include_directories(${PROJECT_NAME} PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../dap-sdk/module/core/include
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../dap-sdk/module/crypto/include
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../dap-sdk/module/crypto/src/rand
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../dap-sdk/module/io/include
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../dap-sdk/module/net/include
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../dap-sdk/module/global-db/include
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../dap-sdk/3rdparty/uthash/src
)

target_link_libraries(${PROJECT_NAME} dap_core dap_crypto dap_chain dap_chain_cs dap_chain_net_srv_stake dap_link_manager)

if (INSTALL_SDK)
set_target_properties(${PROJECT_NAME}  PROPERTIES PUBLIC_HEADER "${DAP_CHAIN_CS_ESBOCS_HEADERS}")
INSTALL(TARGETS ${PROJECT_NAME} 
        LIBRARY DESTINATION lib/modules/consensus/esbocs/
        ARCHIVE DESTINATION lib/modules/consensus/esbocs/
        PUBLIC_HEADER DESTINATION include/modules/consensus/esbocs/ 
        )
endif()
