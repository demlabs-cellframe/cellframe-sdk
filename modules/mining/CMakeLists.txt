cmake_minimum_required(VERSION 3.10)
project (dap_chain_crypto)

# Include LibraryHelpers for object library creation
include(${CMAKE_CURRENT_SOURCE_DIR}/../../cmake/LibraryHelpers.cmake)
  
file(GLOB DAP_CHAIN_CRYPTO_SRCS *.c)

file(GLOB DAP_CHAIN_CRYPTO_HEADERS include/*.h)

# Create OBJECT library instead of STATIC
create_object_library(${PROJECT_NAME} CELLFRAME_INTERNAL_MODULES ${DAP_CHAIN_CRYPTO_SRCS} HEADERS ${DAP_CHAIN_CRYPTO_HEADERS})

# Set definitions and include directories
if(monero_crypto_DEFINITIONS)
    target_compile_definitions(${PROJECT_NAME} PUBLIC ${monero_crypto_DEFINITIONS})
endif()

target_include_directories(dap_chain_crypto INTERFACE .)
target_include_directories(${PROJECT_NAME} PUBLIC include)
if(monero_crypto_INCLUDE_DIRS)
    target_include_directories(${PROJECT_NAME} PUBLIC ${monero_crypto_INCLUDE_DIRS})
endif()

# Link dependencies as INTERFACE for OBJECT library
# Use dap_link_libraries for automatic include propagation with cycle detection
dap_link_libraries(${PROJECT_NAME} INTERFACE dap_core dap_crypto dap_chain monero_crypto)

set(${PROJECT_NAME}_DEFINITIONS CACHE INTERNAL "${PROJECT_NAME}: Definitions" FORCE)
set(${PROJECT_NAME}_INCLUDE_DIRS ${PROJECT_SOURCE_DIR} CACHE INTERNAL "${PROJECT_NAME}: Include Directories" FORCE)

if (${BUILD_DAP_CHAIN_CRYPTO_TESTS} MATCHES ON)
    enable_testing()
    add_subdirectory(test)
endif()

if (INSTALL_SDK)
set_target_properties(${PROJECT_NAME}  PROPERTIES PUBLIC_HEADER "${DAP_CHAIN_CRYPTO_HEADERS}")
INSTALL(TARGETS ${PROJECT_NAME} 
        LIBRARY DESTINATION lib/modules/mining/
        ARCHIVE DESTINATION lib/modules/mining/
        PUBLIC_HEADER DESTINATION include/modules/mining/
)
endif()