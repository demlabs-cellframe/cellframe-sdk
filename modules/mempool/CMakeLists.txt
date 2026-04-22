cmake_minimum_required(VERSION 3.10)
project (dap_chain_mempool)

# Include LibraryHelpers for object library creation
include(${CMAKE_CURRENT_SOURCE_DIR}/../../cmake/LibraryHelpers.cmake)

file(GLOB DAP_CHAIN_MEMPOOL_SRC *.c)
file(GLOB DAP_CHAIN_MEMPOOL_HDR include/*.h)

# Create OBJECT library instead of STATIC
create_object_library(${PROJECT_NAME} CELLFRAME_INTERNAL_MODULES ${DAP_CHAIN_MEMPOOL_SRC} HEADERS ${DAP_CHAIN_MEMPOOL_HDR})

# Link dependencies as INTERFACE for OBJECT library
# Use dap_link_libraries for automatic include propagation with cycle detection
dap_link_libraries(${PROJECT_NAME} INTERFACE dap_http_server dap_client dap_chain_net dap_global_db dap_core dap_json_rpc dap_chain_cs_blocks)

target_include_directories(${PROJECT_NAME} INTERFACE .)
target_include_directories(${PROJECT_NAME} PUBLIC include)
target_include_directories(${PROJECT_NAME} PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/../../../dap-sdk/3rdparty/json-c)

if (INSTALL_SDK)
set_target_properties(${PROJECT_NAME}  PROPERTIES PUBLIC_HEADER "${DAP_CHAIN_MEMPOOL_HDR}")
INSTALL(TARGETS ${PROJECT_NAME} 
        LIBRARY DESTINATION lib/modules/mempool/
        ARCHIVE DESTINATION lib/modules/mempool/
        PUBLIC_HEADER DESTINATION include/modules/mempool/
        )
endif()