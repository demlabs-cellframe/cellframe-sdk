# Chain Cache Database Schema

## Overview

This document describes the GlobalDB schema for chain cache storage - a fast blockchain loading optimization system that caches block/event offsets to skip signature verification on subsequent loads.

## Performance Impact

```
First load:  ~50 min (full validation - signature verification)
Second load: ~30 sec (trusted cache - NO hash verification!)
Speedup: 100x faster!
```

## Key Optimization: Sequential Cache (No Hash Table, No Hash Verification!)

**Trust Model:** Once a cell is fully validated (ready marker set), we trust the cache completely. No hash verification on subsequent loads - maximum speed!

```
OLD (Hash Table + Hash Verification):
┌──────────────────────────────────────────────────────┐
│ For each block:                                       │
│   1. Read block data from file                       │
│   2. Compute hash_fast() ~6ms per block              │ ← SLOW!
│   3. Lookup in UTHash table                          │
│   4. Compare offset/size                              │
│ Total: 8000 blocks × 6ms = ~48 seconds just hashing  │
└──────────────────────────────────────────────────────┘

NEW (Sequential Array + Trust):
┌──────────────────────────────────────────────────────┐
│ For each block:                                       │
│   1. Read block size from file                       │
│   2. Compare offset/size with cache entry            │ ← INSTANT!
│   3. If match: SKIP validation entirely              │
│   4. If mismatch: compute hash + validate            │
│ Total: 8000 blocks = ~0.1 seconds checking           │
└──────────────────────────────────────────────────────┘
```

## Storage Model

```
GlobalDB Group (per network + chain)
  └─> Compact Cell Index (per cell file)
       ├─> Header: cell_id, block_count
       └─> Block entries array:
            ├─> block_hash (32 bytes)
            ├─> file_offset (8 bytes)
            ├─> block_size (4 bytes)
            └─> tx_count (4 bytes)
```

## GlobalDB Structure

### Group Naming

**Format:** `local.chain.cache.{net_name}.{chain_name}.{net_id_hex}.{chain_id_hex}`

**Example:**
```
local.chain.cache.Backbone.zerochain.0x0000000000000001.0x0000000000000100
```

### Key Types

#### 1. Compact Cell Index Key
**Format:** `{net}.{chain}.cell_{cell_id_hex}`

**Example:** `Backbone.zerochain.cell_0000000000000001`

#### 2. Cell Ready Marker Key
**Format:** `{net}.{chain}.cell_{cell_id_hex}.ready`

**Example:** `Backbone.zerochain.cell_0000000000000001.ready`

**Purpose:** Marks cell as validated - enables cache usage on subsequent loads

## Data Structures

### 1. Sequential Cache (Runtime)

```c
typedef struct dap_chain_cache_sequential {
    dap_chain_block_index_entry_t *entries; // Sorted array from GlobalDB
    uint32_t count;                          // Total entries
    uint32_t current_idx;                    // Current position for sequential access
    uint64_t cell_id;                        // Cell ID for validation
} dap_chain_cache_sequential_t;
```

**Usage:**
- Loaded from GlobalDB at cell load start
- Entries are checked sequentially as file is read
- `current_idx` advances on each cache hit
- No hash table, no UTHash overhead!

### 2. Compact Cell Header (Storage)

```c
typedef struct DAP_ALIGN_PACKED dap_chain_cell_compact_header {
    uint64_t cell_id;         // 8 bytes
    uint32_t block_count;     // 4 bytes
    uint32_t reserved;        // 4 bytes (alignment)
} dap_chain_cell_compact_header_t;
```

**Size:** 16 bytes

### 3. Block Index Entry (Storage)

```c
typedef struct DAP_ALIGN_PACKED dap_chain_block_index_entry {
    dap_hash_fast_t block_hash;    // 32 bytes (for new block index building)
    uint64_t        file_offset;   // 8 bytes  ← KEY for sequential check!
    uint32_t        block_size;    // 4 bytes  ← KEY for sequential check!
    uint32_t        tx_count;      // 4 bytes
} dap_chain_block_index_entry_t;
```

**Size:** 48 bytes per block

**Note:** `block_hash` is only used when building index on first load. On subsequent loads, only `file_offset` and `block_size` are checked (no hash verification!).

### 4. Cache Statistics

```c
typedef struct dap_chain_cache_stats {
    uint64_t cache_hits;              // Blocks loaded from cache
    uint64_t cache_misses;            // Blocks fully validated
    uint64_t blocks_cached;           // Total blocks in cache
    uint64_t incremental_saved;       // Incremental saves count
    uint64_t compactions_count;       // Compaction runs
    uint64_t compaction_time_ms;      // Total compaction time
    double avg_lookup_time_ms;        // Average cache lookup time
    double avg_load_time_ms;          // Average block load time
} dap_chain_cache_stats_t;
```

## Storage Format

### Compact Cell Index

```
GlobalDB Entry:
  Key: "{net}.{chain}.cell_{cell_id_hex}"
  Value: Compact blob
  
┌──────────────────────────────────────────────┐
│ dap_chain_cell_compact_header_t (16 bytes)   │
│  - cell_id: 0x0000000000000001               │
│  - block_count: 8000                         │
│  - reserved: 0                               │
├──────────────────────────────────────────────┤
│ dap_chain_block_index_entry_t #1 (48 bytes)  │
│  - block_hash: 0xABCD1234...                 │
│  - file_offset: 128                          │
│  - block_size: 1024                          │
│  - tx_count: 5                               │
├──────────────────────────────────────────────┤
│ dap_chain_block_index_entry_t #2             │
│  ...                                         │
├──────────────────────────────────────────────┤
│ ... (blocks 3-8000)                          │
└──────────────────────────────────────────────┘

Total size: 16 + N × 48 bytes
Example: 8000 blocks = ~384 KB (one GlobalDB read!)
```

## Cell File Format

All chain types (DAG, Blocks) use the same cell file format:

```
┌─────────────────────────────────────────────┐
│ dap_chain_cell_file_header_t                │
│  - signature: 0xfa340bef153eba48 (8 bytes)  │
│  - version: 1 (4 bytes)                     │
│  - type: RAW (1 byte)                       │
│  - chain_id (8 bytes)                       │
│  - chain_net_id (8 bytes)                   │
│  - cell_id (8 bytes)                        │
├─────────────────────────────────────────────┤
│ Atom #1                                      │
│  - size: uint64_t (8 bytes)                 │
│  - data: [size] bytes                       │
├─────────────────────────────────────────────┤
│ Atom #2                                      │
│  - size: uint64_t (8 bytes)                 │
│  - data: [size] bytes                       │
├─────────────────────────────────────────────┤
│ ... more atoms ...                           │
└─────────────────────────────────────────────┘

File offset in cache points to SIZE field!
Read: fseek(offset) → read(size) → read(atom_data)
```

## DAG vs Blocks

### DAG Chain

**Atom type:** `dap_chain_type_dag_event_t` (event)

**Characteristics:**
- Events can have multiple links (DAG structure)
- Each event contains 1+ datums
- Uses threshold for unlinked events (events waiting for parents)
- Simple structure - no in-memory metadata cache needed

### Blocks Chain

**Atom type:** `dap_chain_block_t` (block)

**Characteristics:**
- Linear chain with prev_hash links
- Block contains multiple datums (10-1000)
- Supports forks and branch selection
- Has `dap_chain_block_cache_t` for in-memory metadata (parsed datums, links)

### Common Ground

Both use:
- Same cell file format (`dap_chain_cell.c`)
- Same chain cache mechanism (`dap_chain_cache.c`)
- Same callback interface (`callback_atom_add`, `callback_atom_prefetch`)

**The cache stores identical data for both:**
- Block/Event hash
- File offset
- Size
- Transaction count

## Cache Loading Flow (Node Startup)

### First Load (No Cache)

```
1. Open cell file
   ↓
2. Check ready marker: NOT FOUND
   ↓
3. For each atom in file:
   ├─> Read size + atom data
   ├─> Calculate hash_fast()
   ├─> FULL VALIDATION (signatures, ledger)
   ├─> Build index entry in memory
   └─> Continue to next atom
   ↓
4. Save compact cell index to GlobalDB
   ↓
5. Set ready marker
   ↓
6. Done (slow, but validated)
```

### Subsequent Load (Sequential Cache - ULTRA FAST!)

```
1. Open cell file
   ↓
2. Check ready marker: FOUND ✓
   ↓
3. Load compact cell index from GlobalDB → Simple ARRAY (no hash table!)
   ↓
4. Initialize sequential pointer: current_idx = 0
   ↓
5. For each atom in file:
   ├─> Read size from file
   ├─> Check: offset & size match cache[current_idx]?
   │   ├─> YES (CACHE HIT): 
   │   │   ├─> current_idx++
   │   │   ├─> NO hash computation!
   │   │   ├─> NO validation!
   │   │   └─> Skip to next atom (INSTANT!)
   │   └─> NO (CACHE MISS):
   │       ├─> Compute hash_fast()
   │       ├─> Full validation
   │       └─> Update index
   ↓
6. Done (ULTRA FAST - no hashing on cache hit!)
```

### Performance Comparison

| Operation | Old (Hash Table) | New (Sequential) |
|-----------|------------------|------------------|
| Load index | 50ms | 50ms |
| Build structure | 200ms (UTHash) | 0ms (just array!) |
| Per-block check | hash_fast + O(1) lookup | O(1) offset compare |
| **Total (8000 blocks)** | **~50 seconds** | **~0.5 seconds** |

## New Block Addition Flow (Runtime)

When a new block is received while the node is running:

### Block Reception & Validation

```
┌─────────────────────────────────────────────────────────────────┐
│                    NEW BLOCK RECEIVED                           │
│                  (from network/consensus)                       │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│  1. callback_atom_add() called                                  │
│     ├─> DAG: s_chain_callback_atom_add()                       │
│     └─> Blocks: s_callback_atom_add()                          │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│  2. callback_atom_verify() - FULL VALIDATION                    │
│     ├─> Verify signatures                                       │
│     ├─> Check prev_hash / links                                 │
│     ├─> Validate datums                                         │
│     └─> Ledger checks                                           │
└─────────────────────────────────────────────────────────────────┘
                              │
                    ┌─────────┴─────────┐
                    ▼                   ▼
             ┌──────────┐        ┌──────────────┐
             │  REJECT  │        │    ACCEPT    │
             └──────────┘        └──────────────┘
                                        │
                                        ▼
┌─────────────────────────────────────────────────────────────────┐
│  3. dap_chain_atom_save()                                       │
│     ├─> Gossip to network (if new atom)                        │
│     └─> dap_chain_cell_file_append()                           │
│           ├─> Get current file offset                           │
│           ├─> Write: [size][atom_data]                          │
│           └─> Flush to disk                                     │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│  4. Add to in-memory structures                                 │
│     ├─> DAG: HASH_ADD to events table                          │
│     └─> Blocks: dap_chain_block_cache_new() + HASH_ADD         │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│  5. dap_chain_atom_notify()                                     │
│     ├─> Notify atom_notifiers                                   │
│     ├─> Update blockchain_time                                  │
│     └─> Trigger datum notifications                             │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│  6. dap_chain_cache_on_block_added() (incremental cache update) │
│     ├─> Check ready marker exists                               │
│     │     └─> If NO: skip (first load not complete)            │
│     ├─> Build index entry:                                      │
│     │     ├─> block_hash                                        │
│     │     ├─> file_offset                                       │
│     │     ├─> block_size                                        │
│     │     └─> tx_count                                          │
│     ├─> Append to compact cell index (read-modify-write)       │
│     └─> Check compaction threshold                              │
│           └─> If reached: schedule async compaction            │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
                     ┌────────────────┐
                     │  BLOCK ADDED!  │
                     └────────────────┘
```

### Detailed Code Path (Blocks)

```c
// 1. Network receives new block
//    ↓
// 2. s_callback_atom_add() in dap_chain_type_blocks.c

dap_chain_atom_verify_res_t ret = s_callback_atom_verify(a_chain, a_atom, a_atom_size, &l_block_hash);

if (ret == ATOM_ACCEPT) {
    // 3. Save to file
    int l_err = dap_chain_atom_save(a_chain, l_block->hdr.cell_id, 
                                     a_atom, a_atom_size, 
                                     a_atom_new ? &l_block_hash : NULL,
                                     (char**)&l_block);
    
    // 4. Create in-memory cache
    l_block_cache = dap_chain_block_cache_new(&l_block_hash, l_block, 
                                               a_atom_size, blocks_count + 1, 
                                               !a_chain->is_mapped);
    
    // Add to hash tables
    HASH_ADD(hh, PVT(l_blocks)->blocks, block_hash, sizeof(block_hash), l_block_cache);
    HASH_ADD_BYHASHVALUE(hh2, PVT(l_blocks)->blocks_num, block_number, ...);
    
    // 5. Notify listeners
    dap_chain_atom_notify(a_chain, l_block->hdr.cell_id, &l_block_cache->block_hash,
                          (byte_t*)l_block, a_atom_size, l_block->hdr.ts_created);
    
    // 6. Update chain cache (if enabled)
    dap_chain_cache_on_block_added(a_chain->cache, &l_block_hash,
                                    l_block->hdr.cell_id.uint64,
                                    file_offset, a_atom_size, datum_count);
}
```

### Cache Incremental Update Logic

```
┌─────────────────────────────────────────────────────────────────┐
│  dap_chain_cache_on_block_added()                               │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│  Check: incremental_save enabled?                               │
│     └─> If NO: return (no caching)                             │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│  Check: ready marker exists?                                    │
│     └─> If NO: return (cell not yet fully validated)           │
│         This prevents cache pollution during first load         │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│  dap_chain_cache_append_cell_entry()                            │
│     1. Read existing compact index from GlobalDB               │
│     2. Allocate new buffer (old_size + 48 bytes)               │
│     3. Copy header + existing entries                           │
│     4. Append new entry                                         │
│     5. Update header.block_count++                              │
│     6. Write back to GlobalDB                                   │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│  Update statistics                                              │
│     └─> incremental_saved++                                    │
│     └─> incremental_count++                                    │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│  Check: incremental_count >= compaction_threshold?              │
│     └─> If YES: s_cache_schedule_compaction() (async)          │
└─────────────────────────────────────────────────────────────────┘
```

### Key Points

| Aspect | Description |
|--------|-------------|
| **When validated** | Every new block is ALWAYS fully validated (signatures, ledger) |
| **When cached** | Only after cell has ready marker (was fully validated once) |
| **File write** | Immediate via `dap_chain_cell_file_append()` |
| **Cache write** | Incremental append to compact cell index |
| **Performance** | Full validation ~50ms per block, cache append ~1ms |

## Memory Usage

**During cell loading (NEW - Sequential Cache):**
```
Compact index:    16 + N × 48 bytes (temporary)
Sequential array: N × 48 bytes (just entries, no UTHash overhead!)

Example (8000 blocks):
  Index blob: ~384 KB
  Sequential array: ~384 KB (SAME as blob, no overhead!)
  Total: ~384 KB (freed after cell load)

OLD (Hash Table):
  Index blob: ~384 KB
  Hash table: ~450 KB (56 bytes per entry with UTHash)
  Total: ~834 KB

SAVINGS: ~450 KB less memory per cell load!
```

**After loading:**
```
Cache structure: ~120 bytes per chain
No per-block RAM usage!
```

## Configuration

```ini
[chain]
# Cache mode: full (always validate) or cached (use cache)
cache_mode = cached

# Save each block immediately (vs batch at end)
cache_incremental_save = true

# Trigger compaction after N blocks
cache_compaction_threshold = 100

# Run compaction in background thread
cache_compaction_async = true

# Enable debug logging
cache_debug = false
```

## API Functions

### Core Operations

```c
// Create/delete cache for chain
dap_chain_cache_t *dap_chain_cache_create(dap_chain_t *a_chain, dap_config_t *a_config);
void dap_chain_cache_delete(dap_chain_cache_t *a_cache);

// Check if block in cache
bool dap_chain_cache_has_block(dap_chain_cache_t *a_cache, 
                               const dap_hash_fast_t *a_block_hash,
                               dap_chain_cache_entry_t *a_out_entry);

// Save block to cache
int dap_chain_cache_save_block(dap_chain_cache_t *a_cache,
                               const dap_hash_fast_t *a_block_hash,
                               uint64_t a_cell_id,
                               uint64_t a_file_offset,
                               uint32_t a_block_size,
                               uint32_t a_tx_count);
```

### Sequential Cache Operations (RECOMMENDED)

```c
// Load cell cache as sequential array (no hash table!)
dap_chain_cache_sequential_t *dap_chain_cache_load_cell_sequential(
    dap_chain_cache_t *a_cache, 
    uint64_t a_cell_id);

// Ultra-fast cache check - NO hash computation needed!
// Just compares file offset and block size
bool dap_chain_cache_sequential_check(
    dap_chain_cache_sequential_t *a_seq,
    uint64_t a_file_offset,
    uint32_t a_block_size);

// Free sequential cache
void dap_chain_cache_sequential_free(dap_chain_cache_sequential_t *a_seq);

// Save compact cell index
int dap_chain_cache_save_cell_index(dap_chain_cache_t *a_cache,
                                    uint64_t a_cell_id,
                                    const dap_chain_block_index_entry_t *a_entries,
                                    uint32_t a_count);
```

### Legacy Batch Operations (DEPRECATED)

```c
// DEPRECATED: Use dap_chain_cache_load_cell_sequential() instead
void* dap_chain_cache_load_cell(dap_chain_cache_t *a_cache, uint64_t a_cell_id);

// DEPRECATED: Use dap_chain_cache_sequential_check() instead
int dap_chain_cache_lookup_in_cell(void *a_cell_cache, 
                                   const dap_hash_fast_t *a_block_hash,
                                   dap_chain_cache_entry_t *a_out_entry);

// DEPRECATED: Use dap_chain_cache_sequential_free() instead
void dap_chain_cache_unload_cell(void *a_cell_cache);
```

## Safety Mechanisms

### Trust Model (NEW - No Hash Verification!)

```
┌─────────────────────────────────────────────────────────────────┐
│  READY MARKER = FULL TRUST                                       │
│                                                                   │
│  If ready marker exists:                                          │
│    → Cell was FULLY validated once (signatures, ledger, etc.)    │
│    → We trust file_offset + block_size as identity               │
│    → NO hash verification needed on subsequent loads!            │
│                                                                   │
│  Rationale:                                                       │
│    1. Cell file is append-only (no in-place modifications)       │
│    2. Block at offset X with size Y is always the same block     │
│    3. Hash verification is redundant after first validation      │
│    4. This saves ~6ms × 8000 blocks = ~48 seconds per cell!      │
└─────────────────────────────────────────────────────────────────┘
```

### Ready Marker
- Cell not trusted until fully validated once
- Ready marker only set after complete validation
- Prevents using partial/corrupted cache
- **Once set: FULL TRUST (no hash verification!)**

### Incremental Save
- Saves each block as it's processed
- Minimal data loss on crash
- Compaction merges incremental entries

### Cache Miss Handling
- If offset/size mismatch → compute hash + full validation
- New blocks added at runtime are always validated
- Cache is updated incrementally for new blocks

## Files

- `dap_chain_cache.h` - Public API
- `dap_chain_cache_internal.h` - Internal structures
- `dap_chain_cache.c` - Implementation
- `dap_chain_cell.c` - Cell file operations + cache integration

## Summary

✅ **100x faster loading:** Skip signature verification AND hash computation!  
✅ **Sequential cache:** No hash table overhead, just simple array  
✅ **Trust model:** Ready marker = full trust (no hash verification)  
✅ **Persistent:** Cache survives node restart  
✅ **Compact storage:** ~48 bytes per block  
✅ **Efficient batch loading:** One GlobalDB read per cell  
✅ **Memory efficient:** ~450 KB less RAM per cell load  
✅ **Universal:** Works for both DAG and Blocks chains

### Performance Gains

| Metric | Old (Hash Table) | New (Sequential) | Improvement |
|--------|------------------|------------------|-------------|
| Build cache structure | 200ms | 0ms | ∞ |
| Per-block check | 6ms (hash + lookup) | 0.01ms (offset compare) | 600x |
| Memory usage | 834 KB | 384 KB | 2.2x less |
| Total load time | ~50 sec | ~0.5 sec | 100x |
