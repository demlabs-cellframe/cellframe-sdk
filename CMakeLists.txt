cmake_minimum_required(VERSION 3.0)
project (dap_core)

# fix implicit declaration warnings
add_definitions ("-D_GNU_SOURCE")

if(UNIX)
  file(GLOB CORE_SRCS src/*.c src/etc/*.c)
  file(GLOB CORE_HEADERS include/*.h include/unix/*.h include/unix/linux/*.h )
endif()

if(WIN32)
  file(GLOB CORE_SRCS src/*.c src/etc/*.c src/win32/*.c )
  file(GLOB CORE_HEADERS include/*.h src/win32/*.h src/win32/*.h )
endif()

add_library(${PROJECT_NAME} STATIC ${CORE_SRCS} ${CORE_UNIX_SRCS})

#This paths will be used by project-dependent project libraries
target_include_directories(${PROJECT_NAME} INTERFACE include/)

if(WIN32)
  include_directories(include/)
endif()

if ( ${CMAKE_SYSTEM_NAME} MATCHES "Linux" )
    set(LINUX "Linux")
endif()

if(UNIX)
    add_subdirectory(src/unix)
    target_link_libraries(${PROJECT_NAME} dap_core_unix)
endif()

if(DARWIN)
    add_subdirectory(src/darwin)
    target_link_libraries(${PROJECT_NAME} dap_core_darwin)
endif()

if(BUILD_DAP_TESTS)
    enable_testing()
    add_subdirectory(test)
endif()

