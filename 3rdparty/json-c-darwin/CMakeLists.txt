cmake_minimum_required(VERSION 3.0)
project (json-c)
  
file(GLOB JSON_C_SRCS FILES *.c)
file(GLOB JSON_C_HEADERS FILES *.h)

add_library(${PROJECT_NAME} STATIC ${JSON_C_SRCS} ${JSON_C_HEADERS})
target_include_directories(json-c PUBLIC . )
