cmake_minimum_required(VERSION 3.10)
project (dap_chain_cs_blocks)

# Include LibraryHelpers for object library creation
include(${CMAKE_CURRENT_SOURCE_DIR}/../../../cmake/LibraryHelpers.cmake)
  
file(GLOB DAP_CHAIN_BLOCK_SRCS *.c)
file(GLOB DAP_CHAIN_BLOCK_HEADERS include/*.h)

# Create OBJECT library instead of STATIC
create_object_library(${PROJECT_NAME} CELLFRAME_INTERNAL_MODULES ${DAP_CHAIN_BLOCK_SRCS} HEADERS ${DAP_CHAIN_BLOCK_HEADERS})

if(BUILD_CELLFRAME_SDK_TESTS)
    add_subdirectory(tests)
endif()

# Link dependencies as INTERFACE for OBJECT library
# Use dap_link_libraries for automatic include propagation with cycle detection
dap_link_libraries(${PROJECT_NAME} INTERFACE dap_core dap_crypto dap_chain dap_chain_common dap_cli_server dap_chain_net)

target_include_directories(${PROJECT_NAME} INTERFACE .)
target_include_directories(${PROJECT_NAME} PUBLIC include)

if (INSTALL_SDK)
set_target_properties(${PROJECT_NAME}  PROPERTIES PUBLIC_HEADER "${DAP_CHAIN_BLOCK_HEADERS}")
INSTALL(TARGETS ${PROJECT_NAME} 
        LIBRARY DESTINATION lib/modules/type/blocks/
        ARCHIVE DESTINATION lib/modules/type/blocks/
        PUBLIC_HEADER DESTINATION include/modules/type/blocks/
)
endif()