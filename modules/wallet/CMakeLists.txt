cmake_minimum_required(VERSION 3.10)
project (dap_chain_wallet)

# Include LibraryHelpers for object library creation
include(${CMAKE_CURRENT_SOURCE_DIR}/../../cmake/LibraryHelpers.cmake)

file(GLOB DAP_CHAIN_WALLET_SRCS *.c ../../3rdparty/crc32c_adler/crc32c_adler.c)
file(GLOB DAP_CHAIN_WALLET_HEADERS include/*.h)

# Create OBJECT library instead of STATIC
create_object_library(${PROJECT_NAME} CELLFRAME_INTERNAL_MODULES ${DAP_CHAIN_WALLET_SRCS} HEADERS ${DAP_CHAIN_WALLET_HEADERS})

# Link dependencies as INTERFACE for OBJECT library
# Use dap_link_libraries for automatic include propagation with cycle detection
dap_link_libraries(${PROJECT_NAME} INTERFACE dap_core dap_crypto dap_chain dap_chain_net)

target_include_directories(${PROJECT_NAME} INTERFACE .)
target_include_directories(${PROJECT_NAME} PUBLIC include)
target_include_directories(${PROJECT_NAME} PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/../../3rdparty/crc32c_adler)

if (INSTALL_SDK)
set_target_properties(${PROJECT_NAME}  PROPERTIES PUBLIC_HEADER "${DAP_CHAIN_WALLET_HEADERS}")
INSTALL(TARGETS ${PROJECT_NAME} 
        LIBRARY DESTINATION lib/modules/wallet/
        ARCHIVE DESTINATION lib/modules/wallet/
        PUBLIC_HEADER DESTINATION include/modules/wallet/
)
endif()
