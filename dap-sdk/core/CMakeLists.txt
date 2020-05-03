cmake_minimum_required(VERSION 3.0)
project (dap_core)

# fix implicit declaration warnings
add_definitions ("-D_GNU_SOURCE")

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

if(NOT SUBMODULES_NO_BUILD)

  # Check whether we're on a 32-bit or 64-bit system
  if(CMAKE_SIZEOF_VOID_P EQUAL "8")
    set(DEFAULT_BUILD_64 ON)
  else()
    set(DEFAULT_BUILD_64 OFF)
  endif()
  option(BUILD_64 "Build for 64-bit? 'OFF' builds for 32-bit." ${DEFAULT_BUILD_64})


	if(WIN32)

	  add_definitions ("-DUNDEBUG")
	  add_definitions ("-DNDEBUG")
	  add_definitions ("-DWIN32")
	  add_definitions ("-D_WINDOWS")
	  add_definitions ("-D__WINDOWS__")
	  add_definitions ("-D_CRT_SECURE_NO_WARNINGS")

#	  if(DAP_RELEASE)
	    set(_CCOPT "-mwindows -static -Wall -O3 -fno-ident -ffast-math -ftree-vectorize -mfpmath=sse -mmmx -msse2 -fno-asynchronous-unwind-tables -ffunction-sections -Wl,--gc-sections -Wl,--strip-all")
#	  else()
#	    set(_CCOPT "-mconsole -static -Wall -pg")
#	    set(_LOPT "-mconsole -static -pg")
#	  endif()

	  set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${_CCOPT}")
	  set(CMAKE_LINKER_FLAGS "${CMAKE_LINKER_FLAGS} ${_LOPT}")
  endif()

	if(UNIX)
	  add_definitions ("-DDAP_OS_LINUX")

	  if(DAP_RELEASE)
	    set(_CCOPT "-Wall -O3 -fPIC -fno-pie -no-pie -fno-ident -ffast-math -ftree-vectorize -mfpmath=sse -mmmx -msse2 -fno-asynchronous-unwind-tables -ffunction-sections -Wl,--gc-sections -Wl,--strip-all")
	  else()
	    set(_CCOPT "-Wall -pg -fPIC -fno-pie -no-pie")
	    set(_LOPT "-pg")
	    SET(CMAKE_SHARED_LINKER_FLAGS "${CMAKE_SHARED_LINKER_FLAGS} -pg")
	  endif()

	  set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${_CCOPT}")
	  set(CMAKE_LINKER_FLAGS "${CMAKE_LINKER_FLAGS} ${_LOPT}")
	endif()
endif()

add_library(${PROJECT_NAME} STATIC ${CORE_SRCS} ${CORE_HEADERS})

#This paths will be used by project-dependent project libraries
target_include_directories(${PROJECT_NAME} INTERFACE include/ src/rpmalloc/)

if(WIN32)
  include_directories(include/)
endif()

if ( ${CMAKE_SYSTEM_NAME} MATCHES "Linux" )
    set(LINUX "Linux")
endif()

if(UNIX)
    add_subdirectory(src/unix)
    target_link_libraries(${PROJECT_NAME} dap_core_unix rt)
endif()

if(DARWIN)
    add_subdirectory(src/darwin)
    target_link_libraries(${PROJECT_NAME} dap_core_darwin)
endif()

if(ANDROID)
    add_subdirectory(src/android)
    target_link_libraries(${PROJECT_NAME} dap_core_android)
endif()

if (WIN32)
    add_subdirectory(src/win32)
    target_link_libraries(${PROJECT_NAME} dap_core_win32)
endif()

if(BUILD_DAP_TESTS)
    enable_testing()
    add_subdirectory(test)
endif()
