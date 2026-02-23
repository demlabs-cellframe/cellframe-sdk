cmake_minimum_required(VERSION 3.10)
project (dap_chain_cs_none)

# Include LibraryHelpers for object library creation
include(${CMAKE_CURRENT_SOURCE_DIR}/../../../cmake/LibraryHelpers.cmake)
  
file(GLOB DAP_CHAIN_CS_NO_CONSENSUS_SRC *.c)
file(GLOB DAP_CHAIN_CS_NO_CONSENSUS_HDR include/*.h)

# Create OBJECT library instead of STATIC
create_object_library(${PROJECT_NAME} CELLFRAME_INTERNAL_MODULES ${DAP_CHAIN_CS_NO_CONSENSUS_SRC} HEADERS ${DAP_CHAIN_CS_NO_CONSENSUS_HDR})

# Link dependencies as INTERFACE for OBJECT library
# Use dap_link_libraries for automatic include propagation with cycle detection
dap_link_libraries(${PROJECT_NAME} INTERFACE dap_core dap_chain dap_global_db dap_chain_mempool dap_chain_net)

target_include_directories(${PROJECT_NAME} INTERFACE .)
target_include_directories(${PROJECT_NAME} PUBLIC include)

if (INSTALL_SDK)
set_target_properties(${PROJECT_NAME}  PROPERTIES PUBLIC_HEADER "${DAP_CHAIN_CS_NO_CONSENSUS_HDR}")
INSTALL(TARGETS ${PROJECT_NAME} 
        LIBRARY DESTINATION lib/modules/consensus/none/
        ARCHIVE DESTINATION lib/modules/consensus/none/
        PUBLIC_HEADER DESTINATION include/modules/consensus/none/ 
        )
endif()