cmake_minimum_required(VERSION 3.10)
project (dap_chain_cs_esbocs)

# Include LibraryHelpers for object library creation
include(${CMAKE_CURRENT_SOURCE_DIR}/../../../cmake/LibraryHelpers.cmake)
  
file(GLOB DAP_CHAIN_ESBOCS_SRCS *.c)
file(GLOB DAP_CHAIN_CS_ESBOCS_HEADERS include/*.h)

# Create OBJECT library instead of STATIC
create_object_library(${PROJECT_NAME} CELLFRAME_INTERNAL_MODULES ${DAP_CHAIN_ESBOCS_SRCS} HEADERS ${DAP_CHAIN_CS_ESBOCS_HEADERS})

target_include_directories(${PROJECT_NAME} INTERFACE .)
target_include_directories(${PROJECT_NAME} PUBLIC include)

# Link dependencies as INTERFACE for OBJECT library
# Use dap_link_libraries for automatic include propagation with cycle detection
dap_link_libraries(${PROJECT_NAME} INTERFACE dap_core dap_crypto dap_chain dap_chain_cs_blocks dap_chain_net_srv_stake)

if (INSTALL_SDK)
set_target_properties(${PROJECT_NAME}  PROPERTIES PUBLIC_HEADER "${DAP_CHAIN_CS_ESBOCS_HEADERS}")
INSTALL(TARGETS ${PROJECT_NAME} 
        LIBRARY DESTINATION lib/modules/consensus/esbocs/
        ARCHIVE DESTINATION lib/modules/consensus/esbocs/
        PUBLIC_HEADER DESTINATION include/modules/consensus/esbocs/ 
        )
endif()
