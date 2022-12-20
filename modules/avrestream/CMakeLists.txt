cmake_minimum_required(VERSION 3.10)
project (dap_avrestream)


find_package(PkgConfig REQUIRED)
pkg_search_module(GLIB REQUIRED glib-2.0)
pkg_search_module(GST REQUIRED gstreamer-1.0>=1.6 )
pkg_search_module(GST_PLUGINS_BASE REQUIRED gstreamer-plugins-base-1.0>=1.6 )
pkg_search_module(GST_APP REQUIRED gstreamer-app-1.0>=1.6 )



file(GLOB DAP_AVRESTREAM_SRCS *.c)
file(GLOB DAP_AVRESTREAM_HEADERS include/*.h)

add_library(${PROJECT_NAME} STATIC ${DAP_AVRESTREAM_SRCS} ${DAP_AVRESTREAM_HEADERS})


target_link_libraries(${PROJECT_NAME} ${CELLFRAME_PLUGIN_LIB_LIBRARIES} ${GLIB_LIBRARIES} ${GST_LIBRARIES} ${GST_PLUGINS_BASE_LIBRARIES} ${GST_APP_LIBRARIES} pthread)
target_link_libraries(${PROJECT_NAME} dap_core dap_crypto dap_chain dap_chain_net crc32c_adler)

include_directories(cellframe-sdk/dap-sdk/core/include)
target_include_directories(${PROJECT_NAME} INTERFACE .)
target_include_directories(${PROJECT_NAME} PRIVATE ${GST_INCLUDE_DIRS} ${GST_PLUGINS_BASE_INCLUDE_DIRS} ${GST_APP_INCLUDE_DIRS})


target_include_directories(${PROJECT_NAME} INTERFACE .)
target_include_directories(${PROJECT_NAME} PUBLIC include)
