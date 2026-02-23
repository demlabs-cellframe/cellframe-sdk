cmake_minimum_required(VERSION 3.10)
project (dap_chain)

# Include LibraryHelpers for object library creation
include(${CMAKE_CURRENT_SOURCE_DIR}/../../cmake/LibraryHelpers.cmake)
  
file(GLOB DAP_CHAIN_SRCS *.c)
file(GLOB DAP_CHAIN_HEADERS include/*.h)

# Create OBJECT library instead of STATIC
create_object_library(${PROJECT_NAME} CELLFRAME_INTERNAL_MODULES ${DAP_CHAIN_SRCS} HEADERS ${DAP_CHAIN_HEADERS})

if(BUILD_CELLFRAME_SDK_TESTS)
    add_subdirectory(tests)
endif()

#find_package(PkgConfig REQUIRED)
#pkg_search_module(GLIB REQUIRED glib-2.0)

# Link dependencies as INTERFACE for OBJECT library
# Use dap_link_libraries for automatic include propagation with cycle detection
dap_link_libraries(${PROJECT_NAME} INTERFACE dap_chain_common dap_global_db dap_notify_srv dap_stream ${GLIB_LDFLAGS})

target_include_directories(${PROJECT_NAME} INTERFACE . include/ ${GLIB_INCLUDE_DIRS})
target_include_directories(${PROJECT_NAME} PUBLIC include)

if (INSTALL_SDK)
set_target_properties(${PROJECT_NAME}  PROPERTIES PUBLIC_HEADER "${DAP_CHAIN_HEADERS}")
INSTALL(TARGETS ${PROJECT_NAME} 
        LIBRARY DESTINATION lib/modules/chain/
        ARCHIVE DESTINATION lib/modules/chain/
        PUBLIC_HEADER DESTINATION include/modules/chain/
)
endif()
