#DAP_GLOBAL_DB_TEST - An utility to perfrom DB requests processing in Sync/Async mode


## to Build (it's assume that we already in the CELLFRAME-SDK directory) :
	$ cd test
	$ mkdir build; cd build
	$ cmake ../
	$ make 

## to Run	
	$ ./dap_global_db_test


## an example of session with  build and run steps follows:

```
root@devuan4-sysman:~/Works/cellframe-node-dev-bugfix5461/cellframe-sdk/test# mkdir build ; cd build
root@devuan4-sysman:~/Works/cellframe-node-dev-bugfix5461/cellframe-sdk/test/build# cmake ../ -Wno-dev
-- The C compiler identification is GNU 10.2.1
-- The CXX compiler identification is GNU 10.2.1
-- Detecting C compiler ABI info
-- Detecting C compiler ABI info - done
-- Check for working C compiler: /usr/bin/cc - skipped
-- Detecting C compile features
-- Detecting C compile features - done
-- Detecting CXX compiler ABI info
-- Detecting CXX compiler ABI info - done
-- Check for working CXX compiler: /usr/bin/c++ - skipped
-- Detecting CXX compile features
-- Detecting CXX compile features - done
-- Current DAP SDK path is '/root/Works/cellframe-node-dev-bugfix5461/cellframe-sdk/test/../../cellframe-sdk'. 
        Add '-DDAP_SDK_ROOT=<path_to_sdk>' to cmake if want to change path
-- Current DAP SDK Library path is '/root/Works/cellframe-node-dev-bugfix5461/cellframe-sdk/test/../../build/cellframe-sdk'. 
        Add '-DDAP_LIBSDK_ROOT=<path_to_sdk_library>' to cmake if want to change path
-- Configuring done
-- Generating done
-- Build files have been written to: /root/Works/cellframe-node-dev-bugfix5461/cellframe-sdk/test/build
root@devuan4-sysman:~/Works/cellframe-node-dev-bugfix5461/cellframe-sdk/test/build# make -s
Scanning dependencies of target dap_global_db_test
[ 50%] Building C object CMakeFiles/dap_global_db_test.dir/dap_global_db_test.c.o
In file included from /root/Works/cellframe-node-dev-bugfix5461/cellframe-sdk/test/../../cellframe-sdk/dap-sdk/core/include/dap_strfuncs.h:15,
                 from /root/Works/cellframe-node-dev-bugfix5461/cellframe-sdk/test/dap_global_db_test.c:6:
/root/Works/cellframe-node-dev-bugfix5461/cellframe-sdk/test/../../cellframe-sdk/dap-sdk/core/include/dap_math_ops.h: In function ‘ADD_128_INTO_256’:
/root/Works/cellframe-node-dev-bugfix5461/cellframe-sdk/test/../../cellframe-sdk/dap-sdk/core/include/dap_math_ops.h:418:46: warning: taking address of packed member of ‘struct uint256_t’ may result in an unaligned pointer value [-Waddress-of-packed-member]
  418 |     overflow_flag=SUM_128_128(a_128_bit,temp,&c_256_bit->lo);
      |                                              ^~~~~~~~~~~~~~
/root/Works/cellframe-node-dev-bugfix5461/cellframe-sdk/test/../../cellframe-sdk/dap-sdk/core/include/dap_math_ops.h:427:49: warning: taking address of packed member of ‘struct uint256_t’ may result in an unaligned pointer value [-Waddress-of-packed-member]
  427 |     overflow_flag=SUM_128_128(overflow_128,temp,&c_256_bit->hi);
      |                                                 ^~~~~~~~~~~~~~
/root/Works/cellframe-node-dev-bugfix5461/cellframe-sdk/test/../../cellframe-sdk/dap-sdk/core/include/dap_math_ops.h: In function ‘SUM_256_256’:
/root/Works/cellframe-node-dev-bugfix5461/cellframe-sdk/test/../../cellframe-sdk/dap-sdk/core/include/dap_math_ops.h:436:57: warning: taking address of packed member of ‘struct uint256_t’ may result in an unaligned pointer value [-Waddress-of-packed-member]
  436 |     overflow_flag=SUM_128_128(a_256_bit.lo,b_256_bit.lo,&c_256_bit->lo);
      |                                                         ^~~~~~~~~~~~~~
/root/Works/cellframe-node-dev-bugfix5461/cellframe-sdk/test/../../cellframe-sdk/dap-sdk/core/include/dap_math_ops.h:441:76: warning: taking address of packed member of ‘struct uint256_t’ may result in an unaligned pointer value [-Waddress-of-packed-member]
  441 |     overflow_flag_intermediate=SUM_128_128(intermediate_value,b_256_bit.hi,&c_256_bit->hi);
      |                                                                            ^~~~~~~~~~~~~~
In file included from /root/Works/cellframe-node-dev-bugfix5461/cellframe-sdk/test/dap_global_db_test.c:11:
/root/Works/cellframe-node-dev-bugfix5461/cellframe-sdk/test/../../cellframe-sdk/dap-sdk/crypto/include/dap_hash.h: In function ‘dap_hash_fast’:
/root/Works/cellframe-node-dev-bugfix5461/cellframe-sdk/test/../../cellframe-sdk/dap-sdk/crypto/include/dap_hash.h:74:5: warning: implicit declaration of function ‘SHA3_256’ [-Wimplicit-function-declaration]
   74 |     SHA3_256( (unsigned char *)a_hash_out, (const unsigned char *)a_data_in, a_data_in_size );
      |     ^~~~~~~~
/root/Works/cellframe-node-dev-bugfix5461/cellframe-sdk/test/dap_global_db_test.c: In function ‘s_test_write’:
/root/Works/cellframe-node-dev-bugfix5461/cellframe-sdk/test/dap_global_db_test.c:88:28: warning: assignment to ‘void (*)(const void *)’ from incompatible pointer type ‘void (*)(void *, const void *)’ [-Wincompatible-pointer-types]
   88 |             l_store_obj.cb = s_test_cb_end;                                 /* Callback on request complete should be called */
      |                            ^
[100%] Linking C executable dap_global_db_test
[100%] Built target dap_global_db_test
root@devuan4-sysman:~/Works/cellframe-node-dev-bugfix5461/cellframe-sdk/test/build# ./dap_global_db_test
[03/09/22-13:29:48] [ * ] [dap_events_socket] Initialized events socket module
rm: cannot remove '/dev/mqueue/dap_global_db_test-queue_ptr*': No such file or directory
[03/09/22-13:29:48] [ * ] [dap_timerfd] Initialized timerfd
[03/09/22-13:29:48] [ * ] [dap_events] Initialized event socket reactor for 4 threads
[03/09/22-13:29:48] [ * ] [dap_globaldb_test] Start CuttDB R/W test in Sync mode ...
[03/09/22-13:29:48] [ * ] [dap_globaldb_test] cdb DB driver has been initialized in Sync mode on the ./base.tmp
[03/09/22-13:29:48] [ * ] [dap_globaldb_test] Start writing 1350 records ...
[03/09/22-13:29:49] [ * ] [dap_globaldb_test] Start reading 1350 records ...
[03/09/22-13:29:49] [ * ] [db_driver] DeInit for cdb ...
[03/09/22-13:29:49] [ * ] [dap_globaldb_test] Close global_db
[03/09/22-13:29:49] [ * ] [dap_globaldb_test] Start CuttDB R/W test in Async mode ...
[03/09/22-13:29:49] [ * ] [dap_globaldb_test] cdb DB driver has been initialized in Async mode on the ./base.tmp
[03/09/22-13:29:49] [ * ] [dap_globaldb_test] Start writing 1350 records ...
[03/09/22-13:29:49] [ * ] [dap_globaldb_test] Let's finished DB request ...
[03/09/22-13:29:49] [ * ] [dap_globaldb_test] Callback is called with arg: 0x7ffd30b980fc
[03/09/22-13:29:49] [ * ] [dap_globaldb_test] Start reading 1350 records ...
[03/09/22-13:29:49] [ * ] [db_driver] DeInit for cdb ...
[03/09/22-13:29:49] [ * ] [dap_globaldb_test] Close global_db
[03/09/22-13:29:49] [ * ] [dap_globaldb_test] Start SQLITE3 R/W test in Sync mode ...
[03/09/22-13:29:49] [ * ] [dap_globaldb_test] sqlite DB driver has been initialized in Sync mode on the ./base.tmp
[03/09/22-13:29:49] [ * ] [dap_globaldb_test] Start writing 1350 records ...
[03/09/22-13:29:51] [ * ] [dap_globaldb_test] Start reading 1350 records ...
[03/09/22-13:29:52] [ * ] [dap_globaldb_test] Start SQLITE3 R/W test in Async mode ...
[03/09/22-13:29:52] [ * ] [db_driver] DeInit for sqlite ...
[03/09/22-13:29:52] [ * ] [dap_globaldb_test] sqlite DB driver has been initialized in Async mode on the ./base.tmp
[03/09/22-13:29:52] [ * ] [dap_globaldb_test] Start writing 1350 records ...
[03/09/22-13:29:53] [ * ] [dap_globaldb_test] Let's finished DB request ...
[03/09/22-13:29:53] [ * ] [dap_globaldb_test] Callback is called with arg: 0x7ffd30b980fc
[03/09/22-13:29:53] [ * ] [dap_globaldb_test] Start reading 1350 records ...
[03/09/22-13:29:54] [ * ] [db_driver] DeInit for sqlite ...
root@devuan4-sysman:~/Works/cellframe-node-dev-bugfix5461/cellframe-sdk/test/build# ls -l
total 0
root@devuan4-sysman:~/Works/cellframe-node-dev-bugfix5461/cellframe-sdk/test/build# 
root@devuan4-sysman:~/Works/cellframe-node-dev-bugfix5461/cellframe-sdk/test# ls -l
total 24
-rwxr-xr-x 1 root root  2127 Mar  9 13:35 CMakeLists.txt
-rw-r--r-- 1 root root 11244 Mar  7 23:20 CMakeLists.txt.user
-rwxr-xr-x 1 root root  7864 Mar  9 13:35 dap_global_db_test.c
root@devuan4-sysman:~/Works/cellframe-node-dev-bugfix5461/cellframe-sdk/test# ls -l
total 24
-rwxr-xr-x 1 root root  2127 Mar  9 13:35 CMakeLists.txt
-rw-r--r-- 1 root root 11244 Mar  7 23:20 CMakeLists.txt.user
-rwxr-xr-x 1 root root  7864 Mar  9 13:35 dap_global_db_test.c
root@devuan4-sysman:~/Works/cellframe-node-dev-bugfix5461/cellframe-sdk/test# mkdir build ; cd build
root@devuan4-sysman:~/Works/cellframe-node-dev-bugfix5461/cellframe-sdk/test/build# cmake ../ -Wno-dev
-- The C compiler identification is GNU 10.2.1
-- The CXX compiler identification is GNU 10.2.1
-- Detecting C compiler ABI info
-- Detecting C compiler ABI info - done
-- Check for working C compiler: /usr/bin/cc - skipped
-- Detecting C compile features
-- Detecting C compile features - done
-- Detecting CXX compiler ABI info
-- Detecting CXX compiler ABI info - done
-- Check for working CXX compiler: /usr/bin/c++ - skipped
-- Detecting CXX compile features
-- Detecting CXX compile features - done
-- Current DAP SDK path is '/root/Works/cellframe-node-dev-bugfix5461/cellframe-sdk/test/../../cellframe-sdk'. 
        Add '-DDAP_SDK_ROOT=<path_to_sdk>' to cmake if want to change path
-- Current DAP SDK Library path is '/root/Works/cellframe-node-dev-bugfix5461/cellframe-sdk/test/../../build/cellframe-sdk'. 
        Add '-DDAP_LIBSDK_ROOT=<path_to_sdk_library>' to cmake if want to change path
-- Configuring done
-- Generating done
-- Build files have been written to: /root/Works/cellframe-node-dev-bugfix5461/cellframe-sdk/test/build
root@devuan4-sysman:~/Works/cellframe-node-dev-bugfix5461/cellframe-sdk/test/build# cmake ../ -Wno-dev
-- Current DAP SDK path is '/root/Works/cellframe-node-dev-bugfix5461/cellframe-sdk/test/../../cellframe-sdk'. 
        Add '-DDAP_SDK_ROOT=<path_to_sdk>' to cmake if want to change path
-- Current DAP SDK Library path is '/root/Works/cellframe-node-dev-bugfix5461/cellframe-sdk/test/../../build/cellframe-sdk'. 
        Add '-DDAP_LIBSDK_ROOT=<path_to_sdk_library>' to cmake if want to change path
-- Configuring done
-- Generating done
-- Build files have been written to: /root/Works/cellframe-node-dev-bugfix5461/cellframe-sdk/test/build
root@devuan4-sysman:~/Works/cellframe-node-dev-bugfix5461/cellframe-sdk/test/build# make -s
Scanning dependencies of target dap_global_db_test
[ 50%] Building C object CMakeFiles/dap_global_db_test.dir/dap_global_db_test.c.o
In file included from /root/Works/cellframe-node-dev-bugfix5461/cellframe-sdk/test/../../cellframe-sdk/dap-sdk/core/include/dap_strfuncs.h:15,
                 from /root/Works/cellframe-node-dev-bugfix5461/cellframe-sdk/test/dap_global_db_test.c:6:
/root/Works/cellframe-node-dev-bugfix5461/cellframe-sdk/test/../../cellframe-sdk/dap-sdk/core/include/dap_math_ops.h: In function ‘ADD_128_INTO_256’:
/root/Works/cellframe-node-dev-bugfix5461/cellframe-sdk/test/../../cellframe-sdk/dap-sdk/core/include/dap_math_ops.h:418:46: warning: taking address of packed member of ‘struct uint256_t’ may result in an unaligned pointer value [-Waddress-of-packed-member]
  418 |     overflow_flag=SUM_128_128(a_128_bit,temp,&c_256_bit->lo);
      |                                              ^~~~~~~~~~~~~~
/root/Works/cellframe-node-dev-bugfix5461/cellframe-sdk/test/../../cellframe-sdk/dap-sdk/core/include/dap_math_ops.h:427:49: warning: taking address of packed member of ‘struct uint256_t’ may result in an unaligned pointer value [-Waddress-of-packed-member]
  427 |     overflow_flag=SUM_128_128(overflow_128,temp,&c_256_bit->hi);
      |                                                 ^~~~~~~~~~~~~~
/root/Works/cellframe-node-dev-bugfix5461/cellframe-sdk/test/../../cellframe-sdk/dap-sdk/core/include/dap_math_ops.h: In function ‘SUM_256_256’:
/root/Works/cellframe-node-dev-bugfix5461/cellframe-sdk/test/../../cellframe-sdk/dap-sdk/core/include/dap_math_ops.h:436:57: warning: taking address of packed member of ‘struct uint256_t’ may result in an unaligned pointer value [-Waddress-of-packed-member]
  436 |     overflow_flag=SUM_128_128(a_256_bit.lo,b_256_bit.lo,&c_256_bit->lo);
      |                                                         ^~~~~~~~~~~~~~
/root/Works/cellframe-node-dev-bugfix5461/cellframe-sdk/test/../../cellframe-sdk/dap-sdk/core/include/dap_math_ops.h:441:76: warning: taking address of packed member of ‘struct uint256_t’ may result in an unaligned pointer value [-Waddress-of-packed-member]
  441 |     overflow_flag_intermediate=SUM_128_128(intermediate_value,b_256_bit.hi,&c_256_bit->hi);
      |                                                                            ^~~~~~~~~~~~~~
In file included from /root/Works/cellframe-node-dev-bugfix5461/cellframe-sdk/test/dap_global_db_test.c:11:
/root/Works/cellframe-node-dev-bugfix5461/cellframe-sdk/test/../../cellframe-sdk/dap-sdk/crypto/include/dap_hash.h: In function ‘dap_hash_fast’:
/root/Works/cellframe-node-dev-bugfix5461/cellframe-sdk/test/../../cellframe-sdk/dap-sdk/crypto/include/dap_hash.h:74:5: warning: implicit declaration of function ‘SHA3_256’ [-Wimplicit-function-declaration]
   74 |     SHA3_256( (unsigned char *)a_hash_out, (const unsigned char *)a_data_in, a_data_in_size );
      |     ^~~~~~~~
/root/Works/cellframe-node-dev-bugfix5461/cellframe-sdk/test/dap_global_db_test.c: In function ‘s_test_write’:
/root/Works/cellframe-node-dev-bugfix5461/cellframe-sdk/test/dap_global_db_test.c:88:28: warning: assignment to ‘void (*)(const void *)’ from incompatible pointer type ‘void (*)(void *, const void *)’ [-Wincompatible-pointer-types]
   88 |             l_store_obj.cb = s_test_cb_end;                                 /* Callback on request complete should be called */
      |                            ^
[100%] Linking C executable dap_global_db_test
[100%] Built target dap_global_db_test
root@devuan4-sysman:~/Works/cellframe-node-dev-bugfix5461/cellframe-sdk/test/build# ./ dap_global_db_test
bash: ./: Is a directory
root@devuan4-sysman:~/Works/cellframe-node-dev-bugfix5461/cellframe-sdk/test/build# ./dap_global_db_test
[03/09/22-13:41:44] [ * ] [dap_events_socket] Initialized events socket module
rm: cannot remove '/dev/mqueue/dap_global_db_test-queue_ptr*': No such file or directory
[03/09/22-13:41:44] [ * ] [dap_timerfd] Initialized timerfd
[03/09/22-13:41:44] [ * ] [dap_events] Initialized event socket reactor for 4 threads
[03/09/22-13:41:44] [ * ] [dap_globaldb_test] Start CuttDB R/W test in Sync mode ...
[03/09/22-13:41:44] [ * ] [dap_globaldb_test] cdb DB driver has been initialized in Sync mode on the ./base.tmp
[03/09/22-13:41:44] [ * ] [dap_globaldb_test] Start writing 1350 records ...
[03/09/22-13:41:45] [ * ] [dap_globaldb_test] Start reading 1350 records ...
[03/09/22-13:41:45] [ * ] [db_driver] DeInit for cdb ...
[03/09/22-13:41:45] [ * ] [dap_globaldb_test] Close global_db
[03/09/22-13:41:45] [ * ] [dap_globaldb_test] Start CuttDB R/W test in Async mode ...
[03/09/22-13:41:45] [ * ] [dap_globaldb_test] cdb DB driver has been initialized in Async mode on the ./base.tmp
[03/09/22-13:41:45] [ * ] [dap_globaldb_test] Start writing 1350 records ...
[03/09/22-13:41:45] [ * ] [dap_globaldb_test] Let's finished DB request ...
[03/09/22-13:41:45] [ * ] [dap_globaldb_test] Callback is called with arg: 0x7ffca17a14ec
[03/09/22-13:41:45] [ * ] [dap_globaldb_test] Start reading 1350 records ...
[03/09/22-13:41:46] [ * ] [db_driver] DeInit for cdb ...
[03/09/22-13:41:46] [ * ] [dap_globaldb_test] Close global_db
[03/09/22-13:41:46] [ * ] [dap_globaldb_test] Start SQLITE3 R/W test in Sync mode ...
[03/09/22-13:41:46] [ * ] [dap_globaldb_test] sqlite DB driver has been initialized in Sync mode on the ./base.tmp
[03/09/22-13:41:46] [ * ] [dap_globaldb_test] Start writing 1350 records ...
[03/09/22-13:41:47] [ * ] [dap_globaldb_test] Start reading 1350 records ...
[03/09/22-13:41:47] [ * ] [dap_globaldb_test] Start SQLITE3 R/W test in Async mode ...
[03/09/22-13:41:47] [ * ] [db_driver] DeInit for sqlite ...
[03/09/22-13:41:47] [ * ] [dap_globaldb_test] sqlite DB driver has been initialized in Async mode on the ./base.tmp
[03/09/22-13:41:47] [ * ] [dap_globaldb_test] Start writing 1350 records ...
[03/09/22-13:41:49] [ * ] [dap_globaldb_test] Let's finished DB request ...
[03/09/22-13:41:49] [ * ] [dap_globaldb_test] Let's finished DB request ...
[03/09/22-13:41:49] [ * ] [dap_globaldb_test] Callback is called with arg: 0x7ffca17a14ec
[03/09/22-13:41:49] [ * ] [dap_globaldb_test] Start reading 1350 records ...
[03/09/22-13:41:49] [ * ] [db_driver] DeInit for sqlite ...
root@devuan4-sysman:~/Works/cellframe-node-dev-bugfix5461/cellframe-sdk/test/build#

```
