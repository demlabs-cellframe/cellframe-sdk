cmake_minimum_required(VERSION 3.10)

project(maxminddb C)

add_definitions ("-D_GNU_SOURCE")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fPIC")

file(GLOB maxminddb_src ${CMAKE_CURRENT_SOURCE_DIR}/*.c)
file(GLOB maxminddb_h ${CMAKE_CURRENT_SOURCE_DIR}/*.h)

add_library(${PROJECT_NAME} STATIC ${maxminddb_src} ${maxminddb_h})
set_target_properties(${PROJECT_NAME} PROPERTIES LINKER_LANGUAGE C)
set_target_properties(${PROJECT_NAME} PROPERTIES COMPILER_LANGUAGE C)
target_include_directories(${PROJECT_NAME} INTERFACE .)
target_compile_options(${PROJECT_NAME} PRIVATE -Wno-sign-compare -Wno-pointer-sign)

if (INSTALL_SDK)
set_target_properties(${PROJECT_NAME}  PROPERTIES PUBLIC_HEADER "${maxminddb_h}")

INSTALL(TARGETS ${PROJECT_NAME} 
        LIBRARY DESTINATION lib/modules/net/
        ARCHIVE DESTINATION lib/modules/net/
        PUBLIC_HEADER DESTINATION include/modules/net/maxminddb/        
)
endif()
