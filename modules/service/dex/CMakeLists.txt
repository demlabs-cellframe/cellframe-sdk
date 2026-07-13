cmake_minimum_required(VERSION 3.10)
project (dap_chain_net_srv_dex)

# Include LibraryHelpers for object library creation
include(${CMAKE_CURRENT_SOURCE_DIR}/../../../cmake/LibraryHelpers.cmake)

file(GLOB DEX_SRCS *.c)
file(GLOB DEX_HEADERS include/*.h)

# Create OBJECT library instead of STATIC
create_object_library(${PROJECT_NAME} CELLFRAME_INTERNAL_MODULES ${DEX_SRCS} HEADERS ${DEX_HEADERS})

target_include_directories(${PROJECT_NAME} INTERFACE .)
target_include_directories(${PROJECT_NAME} PUBLIC include)

# Link dependencies as INTERFACE for OBJECT library
dap_link_libraries(${PROJECT_NAME} INTERFACE dap_core dap_crypto dap_chain dap_chain_net dap_chain_net_srv)

if (INSTALL_SDK)
set_target_properties(${PROJECT_NAME}  PROPERTIES PUBLIC_HEADER "${DEX_HEADERS}")
INSTALL(TARGETS ${PROJECT_NAME}
        LIBRARY DESTINATION lib/modules/service/dex/
        ARCHIVE DESTINATION lib/modules/service/dex/
        PUBLIC_HEADER DESTINATION include/modules/service/dex/
)
endif()
