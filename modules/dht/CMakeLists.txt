cmake_minimum_required(VERSION 3.1)
project (dap_chain_dht C)

# Include LibraryHelpers for object library creation
include(${CMAKE_CURRENT_SOURCE_DIR}/../../cmake/LibraryHelpers.cmake)
  
set(DAP_CHAIN_DHT_SRC
            dap_chain_dht.c
    )
set(DAP_CHAIN_DHT_HDR
        include/dap_chain_dht.h
    )
set(DAP_CHAIN_GLOBAL_DB_LIBS dap_core dap_crypto dap_chain)

# Create OBJECT library instead of STATIC
create_object_library(${PROJECT_NAME} CELLFRAME_INTERNAL_MODULES ${DAP_CHAIN_DHT_SRC} HEADERS ${DAP_CHAIN_DHT_HDR})

# Link dependencies as INTERFACE for OBJECT library
# Use dap_link_libraries for automatic include propagation with cycle detection
dap_link_libraries(${PROJECT_NAME} INTERFACE ${DAP_CHAIN_DHT_LIBS})

target_include_directories(${PROJECT_NAME} INTERFACE .)
target_include_directories(${PROJECT_NAME} PUBLIC include)

if (INSTALL_SDK)
set_target_properties(${PROJECT_NAME}  PROPERTIES PUBLIC_HEADER "${DAP_CHAIN_DHT_HDR}")
INSTALL(TARGETS ${PROJECT_NAME} 
        LIBRARY DESTINATION lib/modules/dht/
        ARCHIVE DESTINATION lib/modules/dht/
        PUBLIC_HEADER DESTINATION include/modules/dht/
        )
endif()