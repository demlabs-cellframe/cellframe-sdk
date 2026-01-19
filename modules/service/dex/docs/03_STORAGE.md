# DEX v2 Storage and Caching

## Overview

DEX uses a multi-level storage architecture:

1. **Ledger** — Persistent on-chain storage (source of truth)
2. **Memory Cache** — Hot order cache for fast matching
3. **History Cache** — OHLCV aggregation for analytics

---

## Configuration

```ini
[srv_dex]
memcached=true             # Enable order cache
history_cache=true         # Enable history cache
history_bucket_sec=86400   # Storage bucket size (default: 1 day)
debug_more=true            # Extended debug logging (default)
```

---

## Memory Cache Architecture

### Primary Index (by Root Hash)

```c
static dex_order_cache_entry_t *s_dex_orders_cache = NULL;
```

- Key: `order_root_hash`
- Value: Full order state
- Handle: `entry->level.hh`

### Secondary Index (by Tail Hash)

```c
static dex_order_cache_entry_t *s_dex_index_by_tail = NULL;
```

- Key: `current_tail_hash`
- Value: Same entry as primary
- Handle: `entry->level.hh_tail`
- Purpose: O(1) lookup for updates/purchases

### Pair Index

```c
static dex_pair_index_t *s_dex_pair_index = NULL;
```

Structure:
```c
typedef struct dex_pair_index {
    dex_pair_key_t key;           // Canonical BASE/QUOTE
    dex_order_cache_entry_t *asks; // ASK orders (rate ASC)
    dex_order_cache_entry_t *bids; // BID orders (rate DESC)
    UT_hash_handle hh;
} dex_pair_index_t;
```

- Key: `dex_pair_key_t` (tokens + networks)
- Orders sorted by price (best first)
- Handle: `entry->hh_pair_bucket`

### Seller Index

```c
static dex_seller_index_t *s_dex_seller_index = NULL;
```

Structure:
```c
typedef struct dex_seller_index {
    dap_chain_addr_t seller_addr;
    dex_order_cache_entry_t *entries;
    UT_hash_handle hh;
} dex_seller_index_t;
```

- Key: Seller address
- Purpose: Fast lookup for cancel_all, orders by seller
- Handle: `entry->hh_seller_bucket`

---

## Order Cache Entry

```c
typedef struct dex_order_cache_entry {
    dex_order_level_t level;
    
    // Pointer-only references (no duplication)
    const dex_pair_key_t *pair_key_ptr;
    const dap_chain_addr_t *seller_addr_ptr;
    
    // Bucket handles
    UT_hash_handle hh_pair_bucket;
    UT_hash_handle hh_seller_bucket;
    
    // Metadata
    dap_time_t ts_created, ts_expires;
    uint32_t flags;
    uint8_t side_version;  // bit0=side, bits1-7=version
} dex_order_cache_entry_t;
```

### Order Level (Match Data)

```c
typedef struct dex_order_level {
    dex_order_match_t match;
    UT_hash_handle hh, hh_tail;
} dex_order_level_t;

typedef struct dex_order_match {
    uint256_t value;      // Remaining sell amount
    uint256_t rate;       // Canonical QUOTE/BASE price
    dap_hash_fast_t root; // Order chain root
    dap_hash_fast_t tail; // Current tail TX
    uint8_t min_fill;     // Min fill policy
    int prev_idx;         // OUT_COND index in tail TX
} dex_order_match_t;
```

---

## Cache Synchronization

### Global Lock

```c
static pthread_rwlock_t s_dex_cache_rwlock = PTHREAD_RWLOCK_INITIALIZER;
```

All cache operations use a single RW-lock:
- **Read lock** — Queries, matching, lookups
- **Write lock** — Inserts, updates, deletes, decree callbacks

### Usage Pattern

```c
// Reading
pthread_rwlock_rdlock(&s_dex_cache_rwlock);
dex_order_cache_entry_t *e = NULL;
HASH_FIND(level.hh, s_dex_orders_cache, &hash, sizeof(hash), e);
// ... use e ...
pthread_rwlock_unlock(&s_dex_cache_rwlock);

// Writing
pthread_rwlock_wrlock(&s_dex_cache_rwlock);
// ... modify cache ...
pthread_rwlock_unlock(&s_dex_cache_rwlock);
```

---

## Cache Population (Ledger Notify)

Cache is populated via ledger notification callback:

```c
dap_ledger_tx_add_notify(net->pub.ledger, s_ledger_tx_add_notify_dex, NULL);
```

### Notification Handler

```c
static void s_ledger_tx_add_notify_dex(
    void *a_arg,
    dap_ledger_t *a_ledger,
    dap_chain_datum_tx_t *a_tx,
    dap_hash_fast_t *a_tx_hash,
    dap_chan_ledger_notify_opcodes_t a_opcode
);
```

### Opcodes

| Opcode | Action |
|--------|--------|
| `DAP_LEDGER_NOTIFY_OPCODE_ADDED` (`'a'`) | Add/update order in cache |
| `DAP_LEDGER_NOTIFY_OPCODE_DELETED` (`'d'`) | Remove order from cache (rollback) |

---

## Cache Operations

### Insert/Update (Upsert)

```c
static void s_dex_cache_upsert(
    dap_ledger_t *a_ledger,
    const char *a_sell_token,
    dap_chain_hash_fast_t *a_root,
    dap_chain_hash_fast_t *a_tail,
    dap_chain_tx_out_cond_t *a_cond,
    int a_prev_idx,
    dap_time_t a_ts_created
);
```

1. Find or create seller bucket
2. Find existing entry by root or create new
3. Update tail hash, value, indexes
4. Re-sort pair bucket

### Remove

```c
static void s_dex_cache_remove(dex_order_cache_entry_t *a_entry);
static void s_dex_cache_remove_by_root(dap_chain_hash_fast_t *a_root);
```

1. Remove from tail index
2. Remove from pair bucket (asks/bids)
3. Remove from seller bucket
4. Remove from primary cache
5. Free memory

---

## Pair Bucket Sorting

Orders in pair buckets are sorted for optimal matching:

### ASK Bucket (Rate ASC)

```c
static int s_cmp_entries_ask(dex_order_cache_entry_t *a, dex_order_cache_entry_t *b) {
    int rc = compare256(a->level.match.rate, b->level.match.rate);
    return rc ? rc : s_cmp_entries_ts(a, b);  // FIFO tie-breaker
}
```

Best price = **lowest** QUOTE/BASE rate

### BID Bucket (Rate DESC)

```c
static int s_cmp_entries_bid(dex_order_cache_entry_t *a, dex_order_cache_entry_t *b) {
    int rc = compare256(b->level.match.rate, a->level.match.rate);  // Reversed
    return rc ? rc : s_cmp_entries_ts(a, b);  // FIFO tie-breaker
}
```

Best price = **highest** QUOTE/BASE rate

---

## History Cache (Lite Bucket Architecture)

The history cache uses a "lite bucket" architecture where buckets store only timestamps and trade indices. OHLCV values are computed on-the-fly during queries, enabling flexible candle sizes without storage overhead.

### Structure

```c
typedef struct dex_hist_pair {
    dex_pair_key_t key;
    dex_hist_bucket_t *buckets;          // uthash: ts -> bucket
    dex_hist_trader_idx_t *seller_idx;   // uthash by hh_seller -> seller trades
    dex_hist_trader_idx_t *buyer_idx;    // uthash by hh_buyer  -> buyer trades
    UT_hash_handle hh;
} dex_hist_pair_t;

static dex_hist_pair_t *s_dex_history = NULL;
```

### Lite Bucket

```c
typedef struct dex_hist_bucket {
    uint64_t ts;                          // Bucket start (aligned by s_hist_bucket_ts)
    dex_event_rec_t *events_idx;          // uthash: (tx_hash, prev_tail) -> event
    UT_hash_handle hh;                    // Per-pair bucket hash (key: ts)
} dex_hist_bucket_t;
```

Default bucket size: 86400 seconds (1 day) — aligns to calendar day boundaries.

### Event Record

```c
typedef struct dex_event_rec {
    dex_event_key_t key;                          // (tx_hash, prev_tail)
    const dap_hash_fast_t *order_root_ptr;        // pointer to order root hash (in order_idx)
    const dap_chain_addr_t *seller_addr_ptr;      // pointer to seller addr (in seller_idx)
    const dap_chain_addr_t *buyer_addr_ptr;       // pointer to buyer addr (in buyer_idx)
    uint64_t ts;                                  // event timestamp
    uint256_t price, add_base;                    // canonical QUOTE/BASE price, base delta (quote = price × base)
    uint8_t flags;                                // DEX_OP_* flags
    uint8_t side;                                 // DEX_SIDE_ASK or DEX_SIDE_BID
    struct dex_event_rec *next, *prev;            // utlist DL for seller index
    struct dex_event_rec *buyer_next, *buyer_prev; // utlist DL for buyer index
    struct dex_event_rec *order_next, *order_prev; // utlist DL for order index
    UT_hash_handle hh;                            // uthash in bucket
} dex_event_rec_t;
```

### Event Flags

| Flag | Value | Description |
|------|-------|-------------|
| `DEX_OP_CREATE` | 0x01 | Order creation event |
| `DEX_OP_TARGET` | 0x02 | Trade at specific order (limit) |
| `DEX_OP_MARKET` | 0x04 | Trade at market (best) price |
| `DEX_OP_CANCEL` | 0x08 | Order cancellation event |
| `DEX_OP_UPDATE` | 0x10 | Order parameters update |

### Trader Index (Seller + Buyer)

```c
typedef struct dex_hist_trader_idx {
    dap_chain_addr_t addr;            // shared key for both roles
    dex_event_rec_t *seller_events;   // utlist DL head (seller role)
    dex_event_rec_t *buyer_events;    // utlist DL head (buyer role)
    UT_hash_handle hh_seller;
    UT_hash_handle hh_buyer;
} dex_hist_trader_idx_t;
```

Maintains per-address event lists for both roles.

### Order Index (by order_root)

```c
typedef struct dex_hist_order_idx {
    dap_hash_fast_t order_root;     // order root hash (key)
    dex_event_rec_t *events;        // DL head for events (via order_next/prev)
    UT_hash_handle hh;
} dex_hist_order_idx_t;
```

Enables O(1) lookup of all events for a specific order by its root hash.

**Usage:** `srv_dex history -order <hash>` uses this index for efficient filtering when `history_cache=true`.

**Structure in `dex_hist_pair_t`:**
```c
typedef struct dex_hist_pair {
    dex_pair_key_t key;
    dex_hist_bucket_t *buckets;
    dex_hist_trader_idx_t *seller_idx;
    dex_hist_trader_idx_t *buyer_idx;
    dex_hist_order_idx_t *order_idx;   // uthash by order_root
    UT_hash_handle hh;
} dex_hist_pair_t;
```

**Index Operations:**
- `s_hist_order_idx_get_or_create()` — get or create entry by order_root
- Events linked via `order_next`/`order_prev` pointers in `dex_event_rec_t`
- Entry removed when last event deleted (empty DL head)

### OHLCV Computation

OHLCV is computed on-the-fly from trade records:

```c
typedef struct dex_ohlcv {
    uint64_t ts;
    uint256_t open, high, low, close;
    uint256_t volume_base, volume_quote;
    uint32_t trades;
} dex_ohlcv_t;
```

OHLC (open/high/low/close) is computed from `DEX_OP_MARKET` trades only. Volumes include `MARKET|TARGET` and exclude `CREATE`, `CANCEL`, `UPDATE` records.

Query functions iterate bucket trades and aggregate into requested candle sizes.

### Bucket Alignment

Bucket start is computed by `s_hist_bucket_ts(ts, history_bucket_sec)` with calendar alignment:
- Sub-daily: floor to period
- Daily (86400): 00:00 UTC
- Weekly (604800): Monday 00:00 UTC
- Multi-day (2..27 days): epoch multiples of days
- Monthly (>=28 days): 1st of month 00:00 UTC
- Yearly (>=365 days): Jan 1st 00:00 UTC

Daily alignment (default):

```c
static inline uint64_t s_hist_day_start(uint64_t a_ts) {
    return (a_ts / DAP_SEC_PER_DAY) * DAP_SEC_PER_DAY;
}
```

---

## Pair Whitelist Management

Pairs must be whitelisted via decree before orders can be created:

### Add Pair

```c
static int s_dex_pair_index_add(const dex_pair_key_t *a_key) {
    // Check if already exists
    // Allocate new entry
    // Add to pair index
}
```

### Remove Pair

```c
static int s_dex_pair_index_remove(const dex_pair_key_t *a_key) {
    // Find pair
    // Remove all orders of this pair from cache
    // Delete pair entry
}
```

---

## Cache Dump (Debug)

```c
void dap_chain_net_srv_dex_dump_orders_cache();
void dap_chain_net_srv_dex_dump_history_cache();
```

Outputs:
- Total entries count
- Per-pair order lists
- Per-bucket trade records and counts (plus seller index counts)

---

## Ledger Fallback

When cache is disabled, operations fall back to ledger:

```c
if (s_dex_cache_enabled) {
    // Use cache
    pthread_rwlock_rdlock(&s_dex_cache_rwlock);
    HASH_FIND(...);
    pthread_rwlock_unlock(&s_dex_cache_rwlock);
} else {
    // Ledger fallback
    dap_chain_datum_tx_t *l_tx = dap_ledger_tx_find_by_hash(a_ledger, a_hash);
    // ... extract data from TX ...
}
```

---

## Memory Management

### Initialization

```c
int dap_chain_net_srv_dex_init() {
    // Cache starts empty
    // Populated via ledger notifications as TXs are processed
}
```

### Deinitialization

```c
void dap_chain_net_srv_dex_deinit() {
    pthread_rwlock_wrlock(&s_dex_cache_rwlock);
    
    // Free order cache entries
    HASH_ITER(level.hh, s_dex_orders_cache, e_it, e_tmp) {
        s_dex_indexes_remove(e_it);
        HASH_DELETE(level.hh, s_dex_orders_cache, e_it);
        DAP_DELETE(e_it);
    }
    
    // Free pair index
    HASH_ITER(hh, s_dex_pair_index, pb_it, pb_tmp) {
        HASH_DELETE(hh, s_dex_pair_index, pb_it);
        DAP_DELETE(pb_it);
    }
    
    // Free seller index
    HASH_ITER(hh, s_dex_seller_index, sb_it, sb_tmp) {
        HASH_DELETE(hh, s_dex_seller_index, sb_it);
        DAP_DELETE(sb_it);
    }
    
    // Free history cache
    // ... similar iteration ...
    
    pthread_rwlock_unlock(&s_dex_cache_rwlock);
    pthread_rwlock_destroy(&s_dex_cache_rwlock);
}
```



