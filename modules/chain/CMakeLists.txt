cmake_minimum_required(VERSION 3.10)
project (dap_chain)
  
file(GLOB DAP_CHAIN_SRCS *.c)
file(GLOB DAP_CHAIN_HEADERS include/*.h)

add_library(${PROJECT_NAME} STATIC ${DAP_CHAIN_SRCS} ${DAP_CHAIN_HEADERS})

if(BUILD_CELLFRAME_SDK_TESTS)
    add_subdirectory(tests)
endif()

#find_package(PkgConfig REQUIRED)
#pkg_search_module(GLIB REQUIRED glib-2.0)

target_link_libraries(${PROJECT_NAME} dap_chain_common dap_global_db dap_notify_srv dap_stream ${GLIB_LDFLAGS})
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
