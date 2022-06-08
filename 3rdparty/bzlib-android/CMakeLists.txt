cmake_minimum_required(VERSION 3.10)

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -DHAVE_CONFIG_H -I/usr/lib/jvm/java-8-openjdk-amd64/include/ -I/usr/lib/jvm/java-8-openjdk-amd64/include/linux/")  #-L/usr/lib -l bz2

file(GLOB NATIVE_SRCS "src/*.c")
set(NATIVE_SRCS ${NATIVE_SRCS} "src/bzlib.c")

add_library(bzlib SHARED ${NATIVE_SRCS})

target_link_libraries(bzlib b)
target_include_directories(bzlib PUBLIC "./src")
