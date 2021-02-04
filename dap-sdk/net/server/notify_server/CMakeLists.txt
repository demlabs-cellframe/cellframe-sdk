cmake_minimum_required(VERSION 3.0)
project(dap_notify_srv C)
  
file(GLOB DAP_NOTIFY_SRV_SRCS FILES src/*.c)
file(GLOB DAP_NOTIFY_SRV_HDRS FILES include/*.h)

add_library(${PROJECT_NAME} STATIC ${DAP_NOTIFY_SRV_SRCS} ${DAP_NOTIFY_SRV_HDRS})
target_include_directories(${PROJECT_NAME} INTERFACE . include/)
target_include_directories(${PROJECT_NAME} PUBLIC include)

target_link_libraries(${PROJECT_NAME} dap_core dap_server_core json-c )

