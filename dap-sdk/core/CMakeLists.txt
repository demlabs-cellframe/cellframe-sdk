cmake_minimum_required(VERSION 3.0)
project (dap_core)

add_definitions("-D_GNU_SOURCE") 

if(UNIX)
  file(GLOB CORE_SRCS 
      src/*.c 
      src/etc/*.c
      src/rpmalloc/*.c
  )
  file(GLOB CORE_HEADERS 
      include/*.h 
      include/unix/*.h 
      include/unix/linux/*.h 
  )
endif()

if(WIN32)
  file(GLOB CORE_SRCS 
      src/*.c 
      src/etc/*.c 
      src/rpmalloc/*.c
  )
  file(GLOB CORE_HEADERS 
      include/*.h 
  )
endif()

add_library(${PROJECT_NAME} STATIC ${CORE_SRCS} ${CORE_HEADERS})

target_include_directories(${PROJECT_NAME} PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/../../3rdparty/uthash/src)
#if (WIN32)
#    target_include_directories(${PROJECT_NAME} PRIVATE ../../3rdparty/wepoll)
#endif()

#This paths will be used by project-dependent project libraries
target_include_directories(${PROJECT_NAME} INTERFACE include/ src/rpmalloc/)

if(WIN32)
  include_directories(include/)
endif()

if(UNIX)
    add_subdirectory(src/unix)
    if(DARWIN)
        target_link_libraries(${PROJECT_NAME} dap_core_unix)
    else()
        target_link_libraries(${PROJECT_NAME} dap_core_unix rt)
    endif()
endif()

if(DARWIN)
    add_subdirectory(src/darwin)
    target_link_libraries(${PROJECT_NAME} dap_core_darwin)
endif()

if(ANDROID)
    add_subdirectory(src/android)
    target_link_libraries(${PROJECT_NAME} dap_core_android rt)
endif()

if (WIN32)
    add_subdirectory(src/win32)
    target_link_libraries(${PROJECT_NAME} dap_core_win32)
endif()

if(BUILD_DAP_TESTS)
    enable_testing()
    add_subdirectory(test)
endif()
