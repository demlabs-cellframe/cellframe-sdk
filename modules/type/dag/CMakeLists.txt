cmake_minimum_required(VERSION 3.10)
project (dap_chain_cs_dag)
  
file(GLOB DAP_CHAIN_DAG_SRCS *.c)
file(GLOB DAP_CHAIN_DAG_HEADERS include/*.h)
add_library(${PROJECT_NAME} STATIC ${DAP_CHAIN_DAG_SRCS} ${DAP_CHAIN_DAG_HEADERS})

target_link_libraries(${PROJECT_NAME} dap_core dap_crypto dap_chain dap_chain_net dap_global_db)
target_include_directories(${PROJECT_NAME} INTERFACE .)
target_include_directories(${PROJECT_NAME} PUBLIC include)
target_include_directories(${PROJECT_NAME} PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/../../../../dap-sdk/3rdparty/uthash/src)

if (INSTALL_SDK)
set_target_properties(${PROJECT_NAME}  PROPERTIES PUBLIC_HEADER "${DAP_CHAIN_DAG_HEADERS}")
INSTALL(TARGETS ${PROJECT_NAME} 
        LIBRARY DESTINATION lib/modules/type/dag/
        ARCHIVE DESTINATION lib/modules/type/dag/
        PUBLIC_HEADER DESTINATION include/modules/type/dag/
)
endif()