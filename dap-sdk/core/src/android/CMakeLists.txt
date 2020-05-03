cmake_minimum_required(VERSION 3.0)

project (dap_core_android C)

file(GLOB CORE_ANDROID_SRCS *.c)
file(GLOB CORE_ANDROID_HEADERS *.h)

add_library(${PROJECT_NAME} STATIC ${CORE_ANDROID_SRCS} ${CORE_ANDROID_HEADERS})

#target_link_libraries(${PROJECT_NAME} dap_core pthread)

target_include_directories(${PROJECT_NAME} INTERFACE .)


