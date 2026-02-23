cmake_minimum_required(VERSION 3.10)
project (dap_chain_cs_block_pow)

# Include LibraryHelpers for object library creation
include(${CMAKE_CURRENT_SOURCE_DIR}/../../../cmake/LibraryHelpers.cmake)
  
file(GLOB DAP_CHAIN_BLOCK_CS_POW_SRCS *.c)
file(GLOB DAP_CHAIN_BLOCK_CS_POW_HEADERS include/*.h)

# Create OBJECT library instead of STATIC
create_object_library(${PROJECT_NAME} CELLFRAME_INTERNAL_MODULES ${DAP_CHAIN_BLOCK_CS_POW_SRCS} HEADERS ${DAP_CHAIN_BLOCK_CS_POW_HEADERS})


# Link dependencies as INTERFACE for OBJECT library
# Use dap_link_libraries for automatic include propagation with cycle detection
dap_link_libraries(${PROJECT_NAME} INTERFACE dap_core dap_crypto dap_chain dap_chain_cs_blocks)

target_include_directories(${PROJECT_NAME} INTERFACE .)

if (INSTALL_SDK)
set_target_properties(${PROJECT_NAME}  PROPERTIES PUBLIC_HEADER "${DAP_CHAIN_BLOCK_CS_POW_HEADERS}")
INSTALL(TARGETS ${PROJECT_NAME} 
        LIBRARY DESTINATION lib/modules/consensus/block-pow/
        ARCHIVE DESTINATION lib/modules/consensus/block-pow/
        PUBLIC_HEADER DESTINATION include/modules/consensus/block-pow/
)
endif()