cmake_minimum_required(VERSION 3.10)
project (dap_chain)
  
# Exclude files moved to common and consensus modules
file(GLOB DAP_CHAIN_SRCS *.c)
file(GLOB DAP_CHAIN_HEADERS include/*.h)

# Use universal Cellframe library macro
cellframe_add_library(${PROJECT_NAME} ${DAP_CHAIN_SRCS} HEADERS ${DAP_CHAIN_HEADERS})

if(BUILD_CELLFRAME_SDK_TESTS)
    add_subdirectory(tests)
endif()

target_link_libraries(${PROJECT_NAME} dap_common dap_global_db dap_notify_srv dap_stream dap_chain_cs dap_chain_datum)
target_include_directories(${PROJECT_NAME} INTERFACE . include/)
target_include_directories(${PROJECT_NAME} PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)

if (INSTALL_SDK)
set_target_properties(${PROJECT_NAME}  PROPERTIES PUBLIC_HEADER "${DAP_CHAIN_HEADERS}")
INSTALL(TARGETS ${PROJECT_NAME} 
        LIBRARY DESTINATION lib/modules/chain/
        ARCHIVE DESTINATION lib/modules/chain/
        PUBLIC_HEADER DESTINATION include/modules/chain/
)
endif()
