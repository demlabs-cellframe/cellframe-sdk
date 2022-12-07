cmake_minimum_required(VERSION 3.10)
project (json-c)

add_definitions("-D_GNU_SOURCE")

file(GLOB JSON_C_SRCS FILES *.c)
file(GLOB JSON_C_HEADERS FILES *.h)

add_library(${PROJECT_NAME} STATIC ${JSON_C_SRCS} ${JSON_C_HEADERS})
target_include_directories(${PROJECT_NAME} PUBLIC . )
target_include_directories(${PROJECT_NAME} PUBLIC ../../3rdparty/)
