cmake_minimum_required(VERSION 2.8)
project (dap_http)
  
set(HTTP_SRCS dap_http_client.c dap_http_client_simple.c dap_http_header.c)
 
add_library(${PROJECT_NAME} STATIC ${HTTP_SRCS})

