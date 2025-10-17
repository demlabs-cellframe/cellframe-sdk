# CMake generated Testfile for 
# Source directory: /home/naeper/work/cellframe-node/cellframe-sdk/tests/integration
# Build directory: /home/naeper/work/cellframe-node/cellframe-sdk/build-test/tests/integration
# 
# This file includes the relevant testing commands required for 
# testing this directory and lists subdirectories to be tested as well.
add_test(utxo_blocking_integration "/home/naeper/work/cellframe-node/cellframe-sdk/build-test/tests/integration/utxo_blocking_integration_test")
set_tests_properties(utxo_blocking_integration PROPERTIES  LABELS "integration;utxo;blocking;ledger" TIMEOUT "120" _BACKTRACE_TRIPLES "/home/naeper/work/cellframe-node/cellframe-sdk/tests/integration/CMakeLists.txt;28;add_test;/home/naeper/work/cellframe-node/cellframe-sdk/tests/integration/CMakeLists.txt;0;")
