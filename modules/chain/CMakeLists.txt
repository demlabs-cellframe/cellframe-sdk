cmake_minimum_required(VERSION 3.10)
project (dap_chain)
  
# Exclude files moved to common module
set(DAP_CHAIN_SRCS 
    dap_chain.c
    dap_chain_cell.c
    dap_chain_cs_class.c
)
file(GLOB DAP_CHAIN_HEADERS include/*.h)

# Use universal Cellframe library macro
cellframe_add_library(${PROJECT_NAME} ${DAP_CHAIN_SRCS} HEADERS ${DAP_CHAIN_HEADERS})

if(BUILD_CELLFRAME_SDK_TESTS)
    add_subdirectory(tests)
endif()

#find_package(PkgConfig REQUIRED)
#pkg_search_module(GLIB REQUIRED glib-2.0)

target_link_libraries(${PROJECT_NAME} dap_common dap_chain_datum dap_global_db dap_notify_srv dap_stream dap_chain_cs ${GLIB_LDFLAGS})
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
