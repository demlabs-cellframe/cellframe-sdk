cmake_minimum_required(VERSION 3.10)
project (dap_chain_net_srv_datum_pool)

# Include LibraryHelpers for object library creation
include(${CMAKE_CURRENT_SOURCE_DIR}/../../../cmake/LibraryHelpers.cmake)
  
file(GLOB DAP_CHAIN_NET_SRV_DATUM_POOL_SRCS *.c)
file(GLOB DAP_CHAIN_NET_SRV_DATUM_POOL_HEADERS include/*.h)

# Create OBJECT library instead of STATIC
create_object_library(${PROJECT_NAME} CELLFRAME_INTERNAL_MODULES ${DAP_CHAIN_NET_SRV_DATUM_POOL_SRCS} HEADERS ${DAP_CHAIN_NET_SRV_DATUM_POOL_HEADERS})

# Link dependencies as INTERFACE for OBJECT library
# Use dap_link_libraries for automatic include propagation with cycle detection
dap_link_libraries(${PROJECT_NAME} INTERFACE dap_chain_net_srv dap_chain_net_srv_datum)

target_include_directories(${PROJECT_NAME} INTERFACE .)
target_include_directories(${PROJECT_NAME} PUBLIC include)

if (INSTALL_SDK)
set_target_properties(${PROJECT_NAME}  PROPERTIES PUBLIC_HEADER "${DAP_CHAIN_NET_SRV_DATUM_POOL_HEADERS}")
INSTALL(TARGETS ${PROJECT_NAME} 
        LIBRARY DESTINATION lib/modules/service/mining-pool/
        ARCHIVE DESTINATION lib/modules/service/mining-pool/
        PUBLIC_HEADER DESTINATION include/modules/service/mining-pool/
)
endif()