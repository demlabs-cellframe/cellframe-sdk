cmake_minimum_required(VERSION 3.10)

project(core_test)

set(CMAKE_C_STANDARD 11)
file(GLOB SRCS *.c)

add_subdirectory(libdap-test)

if(UNIX)
    file(GLOB PLATROFM_DEP_SRC unix/*.c unix/*.h)
endif()

add_executable(${PROJECT_NAME} ${SRCS} ${PLATROFM_DEP_SRC})  
target_link_libraries(core_test dap_test dap_core pthread)

add_executable(rpmalloc_test
  rpmalloc/test/main.c 
  rpmalloc/test/thread.c
  rpmalloc/test/timer.c
)
target_link_libraries(rpmalloc_test dap_core pthread)
target_include_directories(rpmalloc_test PRIVATE rpmalloc/test/)

add_executable(rpmalloc_bench
  rpmalloc/benchmark/main.c 
  rpmalloc/benchmark/benchmark.c
  rpmalloc/test/thread.c
  rpmalloc/test/timer.c
)
if(WIN32)
	target_link_libraries(rpmalloc_bench dap_core m pthread ntdll psapi Shlwapi)
endif()
if(UNIX)
	target_link_libraries(rpmalloc_bench dap_core m pthread)
endif()
	target_include_directories(rpmalloc_bench PRIVATE rpmalloc/benchmark/ rpmalloc/test/)

add_executable(crtmalloc_bench
  rpmalloc/benchmark/main.c 
  rpmalloc/benchmark/crt_benchmark.c
  rpmalloc/test/thread.c
  rpmalloc/test/timer.c
)
if(WIN32)
	target_link_libraries(crtmalloc_bench dap_core m pthread ntdll psapi Shlwapi)
endif()
if(UNIX)
	target_link_libraries(crtmalloc_bench dap_core m pthread)
endif()
target_include_directories(crtmalloc_bench PRIVATE rpmalloc/benchmark/ rpmalloc/test/)

add_test(
    NAME core-test
    COMMAND core_test
)

add_test(
    NAME rpm-test
    COMMAND rpmalloc
)

if(UNIX)
    target_include_directories(${PROJECT_NAME} PRIVATE unix)
    target_include_directories(${PROJECT_NAME} PRIVATE unix/linux)
endif()
