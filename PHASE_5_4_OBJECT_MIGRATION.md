# Phase 5.4: Migration to OBJECT Libraries (Clean Architecture)

**Date**: 2025-12-16  
**Status**: IN_PROGRESS  
**Goal**: Eliminate ALL cyclic dependencies and convert ALL modules to OBJECT libraries

---

## 🎯 Objective

**Convert Cellframe SDK from STATIC to OBJECT libraries** following DAP SDK pattern:
- ✅ No intermediate `.a` files
- ✅ All modules compiled to `.o` files
- ✅ Single final `libcellframe_sdk.so` with ALL symbols
- ✅ NO cyclic dependencies (CMake enforces this for OBJECT libs)
- ✅ Proper include propagation through dependencies, NOT manual paths

---

## ❌ FORBIDDEN (SLC Violations)

**NEVER use these anti-patterns:**
```cmake
# ❌ WRONG: Manual include paths bypass dependency graph
target_include_directories(module PRIVATE ${CMAKE_SOURCE_DIR}/other_module/include)

# ❌ WRONG: STATIC libraries hide architectural problems
add_library(module STATIC ...)

# ❌ WRONG: --whole-archive is a linker hack
target_link_libraries(... -Wl,--whole-archive ...)
```

**✅ CORRECT approach:**
```cmake
# ✅ Include paths propagate automatically through target_link_libraries
target_link_libraries(module_a module_b)  # module_a gets module_b's INTERFACE_INCLUDE_DIRECTORIES

# ✅ If cycle exists → break it architecturally (API Layer / Callbacks)
# Don't add manual includes - FIX THE ARCHITECTURE
```

---

## 📊 Current State

### Converted to OBJECT ✅
- `dap_common` ✅
- `dap_chain_datum` ✅
- `dap_chain_wallet` ✅ (removed net/mempool deps)
- `dap_chain` ✅
- `dap_chain_ledger` ✅
- `dap_chain_node_cli_cmd` ✅
- `dap_chain_mempool` ✅
- `dap_chain_net` ✅
- `dap_chain_net_srv` ✅
- `dap_chain_cs` ✅
- `dap_chain_cs_esbocs` ✅ (removed blocks/net_srv/net deps)
- `dap_chain_type_blocks` ✅ (removed mempool/stake deps)
- `dap_chain_net_srv_stake` ✅ (removed net/net_srv/compose/cs deps)
- `dap_compose` ✅ (removed wallet deps)
- All service modules ✅
- `dap_chain_type_dag` ✅
- `dap_chain_type_dag_poa` ✅
- `dap_chain_type_none` ✅

### Cycles Broken ✅
1. **blocks ↔ mempool**: Include path only (mempool can use blocks symbols from final lib)
2. **blocks ↔ stake**: Callback API (`dap_chain_block_callbacks`) ✅
3. **esbocs ↔ blocks**: Include path only
4. **stake ↔ compose**: Removed compose from stake deps
5. **wallet ↔ net/mempool**: Removed from wallet deps

---

## 🔧 Remaining Work

### Phase 5.4.1: Remove ALL Manual Include Paths ⏳
**Current violations:**
- `modules/type/blocks/CMakeLists.txt` - has manual includes to mempool/stake
- `modules/consensus/esbocs/CMakeLists.txt` - has manual includes
- `modules/service/stake/CMakeLists.txt` - has manual includes
- `modules/compose/CMakeLists.txt` - has manual includes  
- `modules/wallet/CMakeLists.txt` - has manual includes

**Action**: Replace with proper architectural dependencies or API layers.

### Phase 5.4.2: Verify ALL Symbols Exported ⏳
- Test that ALL functions are available through `cellframe_sdk.so`
- No undefined references in tests
- Headers propagate correctly to test executables

### Phase 5.4.3: Full Test Suite Pass ⏳
- All tests compile
- All tests link
- All tests pass

---

## ✅ Success Criteria

1. ✅ CMake generates without cycle errors
2. ✅ ALL modules are OBJECT libraries
3. ✅ NO manual `target_include_directories` to other modules
4. ✅ ALL symbols exported from `cellframe_sdk.so`
5. ✅ Tests compile and link using ONLY `cellframe_sdk`
6. ✅ Full build: `make` completes 100%
7. ✅ Tests pass: `make test` succeeds

**Only then is Phase 5 truly complete!**

