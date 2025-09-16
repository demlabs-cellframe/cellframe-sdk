# Distributed under the OSI-approved BSD 3-Clause License.  See accompanying
# file Copyright.txt or https://cmake.org/licensing for details.

cmake_minimum_required(VERSION 3.5)

file(MAKE_DIRECTORY
  "/Users/danilmartynenko/DeveloperSpace/Demlabs/dapchainvpn/dapchainvpn-client/cellframe-sdk/dap-sdk/3rdparty/json-c"
  "/Users/danilmartynenko/DeveloperSpace/Demlabs/dapchainvpn/dapchainvpn-client/cellframe-sdk/build_osx_release/build/dap-sdk/dap_json-c_dep-prefix/src/dap_json-c_dep-build"
  "/Users/danilmartynenko/DeveloperSpace/Demlabs/dapchainvpn/dapchainvpn-client/cellframe-sdk/build_osx_release/build/dap-sdk/dap_json-c_dep-prefix"
  "/Users/danilmartynenko/DeveloperSpace/Demlabs/dapchainvpn/dapchainvpn-client/cellframe-sdk/build_osx_release/build/dap-sdk/dap_json-c_dep-prefix/tmp"
  "/Users/danilmartynenko/DeveloperSpace/Demlabs/dapchainvpn/dapchainvpn-client/cellframe-sdk/build_osx_release/build/dap-sdk/dap_json-c_dep-prefix/src/dap_json-c_dep-stamp"
  "/Users/danilmartynenko/DeveloperSpace/Demlabs/dapchainvpn/dapchainvpn-client/cellframe-sdk/build_osx_release/build/dap-sdk/dap_json-c_dep-prefix/src"
  "/Users/danilmartynenko/DeveloperSpace/Demlabs/dapchainvpn/dapchainvpn-client/cellframe-sdk/build_osx_release/build/dap-sdk/dap_json-c_dep-prefix/src/dap_json-c_dep-stamp"
)

set(configSubDirs )
foreach(subDir IN LISTS configSubDirs)
    file(MAKE_DIRECTORY "/Users/danilmartynenko/DeveloperSpace/Demlabs/dapchainvpn/dapchainvpn-client/cellframe-sdk/build_osx_release/build/dap-sdk/dap_json-c_dep-prefix/src/dap_json-c_dep-stamp/${subDir}")
endforeach()
if(cfgdir)
  file(MAKE_DIRECTORY "/Users/danilmartynenko/DeveloperSpace/Demlabs/dapchainvpn/dapchainvpn-client/cellframe-sdk/build_osx_release/build/dap-sdk/dap_json-c_dep-prefix/src/dap_json-c_dep-stamp${cfgdir}") # cfgdir has leading slash
endif()
