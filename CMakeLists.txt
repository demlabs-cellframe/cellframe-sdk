project(DapServer)
cmake_minimum_required(VERSION 2.8)

SET (CMAKE_INSTALL_PREFIX "/opt/dapserver")
SET (CPACK_INSTALL_PREFIX "/opt/dapserver")

SET (DESTDIR "/opt/dapserver")

SET (DAP_MODULES "serverlist")


if(${DAP_MODULES} MATCHES "serverlist")
    add_definitions(-DDAP_MOD_SERVER_LIST)
endif()

set(SERVER_SRCS  main.c)


include_directories("${INCLUDE_DIRECTORIES} ${dapcore_INCLUDE_DIRS}")
include_directories("${INCLUDE_DIRECTORIES} ${dapcrypt_INCLUDE_DIRS}")
include_directories("${INCLUDE_DIRECTORIES} ${daphttp_INCLUDE_DIRS}")
include_directories("${INCLUDE_DIRECTORIES} ${dapauth_INCLUDE_DIRS}")
include_directories("${INCLUDE_DIRECTORIES} ${dapdb_INCLUDE_DIRS}")
include_directories("${INCLUDE_DIRECTORIES} ${dapdb_http_INCLUDE_DIRS}")
include_directories("${INCLUDE_DIRECTORIES} ${dapmedia_INCLUDE_DIRS}")
include_directories("${INCLUDE_DIRECTORIES} ${dapsession_INCLUDE_DIRS}")
include_directories("${INCLUDE_DIRECTORIES} ${dapstream_INCLUDE_DIRS}")
include_directories("${INCLUDE_DIRECTORIES} ${dapmodserverlist_INCLUDE_DIRS}")
include_directories("${INCLUDE_DIRECTORIES} ${dapmodmcod_INCLUDE_DIRS}")
include_directories("${INCLUDE_DIRECTORIES} ${dapmodchats_INCLUDE_DIRS}")
include_directories("${INCLUDE_DIRECTORIES} ${dapmodvpn_INCLUDE_DIRS}")
include_directories("${INCLUDE_DIRECTORIES} ${MONGO_INCLUDE_DIRS}")

add_definitions ("${dapcore_DEFINITIONS}")
add_definitions ("${dapcrypt_DEFINITIONS}")
add_definitions ("${dapdb_DEFINITIONS}")
add_definitions ("${dapdb_http_DEFINITIONS}")
add_definitions ("${dapauth_DEFINITIONS}")
add_definitions ("${daphttp_DEFINITIONS}")
add_definitions ("${dapstream_DEFINITIONS}")
add_definitions ("${dapmedia_DEFINITIONS}")
add_definitions ("${dapsession_DEFINITIONS}")

add_executable(${PROJECT_NAME} ${SERVER_SRCS})
target_link_libraries(${PROJECT_NAME} dapmodserverlist dapmodchats dapmodmcod dapmodvpn  dapdb daphttp dapauth dapdb_http  dapmedia dapstream dapsession  dapcrypt dapcore m crypto pthread magic config gstapp-1.0 ${BSON_LIBRARIES} ${MONGO_LIBRARIES} ${GST_LIBRARIES})

SET( CPACK_GENERATOR "DEB")
SET( CPACK_PACKAGE_NAME  "dapserver")
SET( CPACK_PACKAGE_VERSION_MAJOR 1)
SET( CPACK_PACKAGE_VERSION_MINOR 1)
SET( CPACK_PACKAGE_VERSION_PATCH 5)

SET( CPACK_SYSTEM_NAME "debian-9.1-amd64")

SET( CPACK_DEBIAN_PACKAGE_MAINTAINER "Nier Automata <nier@ldemlabs.net>" )
SET( CPACK_DEBIAN_PACKAGE_DESCRIPTION_SUMMARY "Dap Server" )
SET( CPACK_DEBIAN_PACKAGE_DESCRIPTION 	"DAP server" )
SET( CPACK_DEBIAN_PACKAGE_SECTION "extra")
SET( CPACK_DEBIAN_PACKAGE_ARCHITECTURE "amd64" )
SET( CPACK_DEBIAN_PACKAGE_DEPENDS "debconf (>=1.5), dpkg (>=1.17), bash (>=4), mongodb (>=1)")
SET( CPACK_DEBIAN_PACKAGE_SHLIBDEPS ON)
SET( CPACK_DEBIAN_PACKAGE_CONTROL_EXTRA
    "${CMAKE_CURRENT_SOURCE_DIR}/debian/postinst;${CMAKE_CURRENT_SOURCE_DIR}/debian/postrm;${CMAKE_CURRENT_SOURCE_DIR}/debian/templates;${CMAKE_CURRENT_SOURCE_DIR}/debian/config;")

INSTALL(DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/dist/ DESTINATION ${CMAKE_INSTALL_PREFIX} FILES_MATCHING PATTERN "*"  PATTERN "*")
INSTALL(TARGETS DapServer DESTINATION ${CMAKE_INSTALL_PREFIX}/bin )
INSTALL(DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/scripts/ DESTINATION ${CMAKE_INSTALL_PREFIX}/bin FILES_MATCHING PATTERN "*"  PATTERN "*" PERMISSIONS OWNER_EXECUTE;OWNER_READ;OWNER_WRITE;WORLD_READ;GROUP_READ )
INCLUDE(CPack)
