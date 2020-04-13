if(${CMAKE_SYSTEM_NAME} MATCHES "Linux")
    set(OS_TYPE_DESKTOP ON)
    set(LINUX ON)
    set(UNIX ON)
    EXECUTE_PROCESS( COMMAND cat /etc/os-release COMMAND grep VERSION_CODENAME COMMAND sed s/VERSION_CODENAME=// COMMAND tr -d '\n' OUTPUT_VARIABLE L_DEBIAN_OS_NAME)
    EXECUTE_PROCESS( COMMAND cat /etc/os-release COMMAND grep VERSION_ID COMMAND sed s/VERSION_ID=// COMMAND tr -d '\n' COMMAND sed s/\\x22// COMMAND sed s/\\x22// OUTPUT_VARIABLE L_DEBIAN_OS_VERSION)
    SET(DEBIAN_OS_NAME "${L_DEBIAN_OS_NAME}")
    SET(DEBIAN_OS_VERSION ${L_DEBIAN_OS_VERSION})
    message("Debian OS ${DEBIAN_OS_VERSION} (${DEBIAN_OS_NAME})")
# check if we're building natively on Android (TERMUX)
    EXECUTE_PROCESS( COMMAND uname -o COMMAND tr -d '\n' OUTPUT_VARIABLE OPERATING_SYSTEM)
elseif(${CMAKE_SYSTEM_NAME} MATCHES "Android")
    message("ANDROID")
    set(ANDROID ON)
    set(UNIX ON)
    set(LINUX ON)
    set(OS_TYPE_MOBILE ON)
    message("ANDROID build")
    add_definitions(-DANDROID -DDAP_OS_ANDROID)
elseif(${CMAKE_SYSTEM_NAME} MATCHES "Win")
    message("Win build")
    set(OS_TYPE_DESKTOP ON)
endif()
