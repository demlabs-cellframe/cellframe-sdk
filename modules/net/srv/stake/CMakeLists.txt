cmake_minimum_required(VERSION 3.10)
project(dap_chain_net_srv_stake_common)

# Header-only module with common stake types
# NO source files - just type definitions

file(GLOB DAP_STAKE_COMMON_HEADERS include/*.h)

# Use universal Cellframe library macro (creates OBJECT library, even if empty)
# This ensures proper include propagation through target_link_libraries
add_library(${PROJECT_NAME} INTERFACE)

# Export include directory
target_include_directories(${PROJECT_NAME} INTERFACE 
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    $<INSTALL_INTERFACE:include/modules/net-srv-stake>
)

# Minimal dependencies (only common types)
target_link_libraries(${PROJECT_NAME} INTERFACE dap_common)

message(STATUS "[Cellframe] Module: ${PROJECT_NAME} (INTERFACE - header-only stake types)")

if (INSTALL_SDK)
    set_target_properties(${PROJECT_NAME} PROPERTIES PUBLIC_HEADER "${DAP_STAKE_COMMON_HEADERS}")
    INSTALL(TARGETS ${PROJECT_NAME}
        EXPORT ${PROJECT_NAME}_targets
        PUBLIC_HEADER DESTINATION include/modules/net-srv-stake/
    )
endif()









