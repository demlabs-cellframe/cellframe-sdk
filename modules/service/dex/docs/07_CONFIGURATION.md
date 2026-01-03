# DEX v2 Configuration and Governance

## Node Configuration

### Config File Location

```
/opt/cellframe-node/etc/cellframe-node.cfg
```

### DEX Section

```ini
[srv_dex]
# Enable in-memory order cache for fast matching
memcached=true

# Enable OHLCV history cache
history_cache=true

# History bucket size in seconds (default: 86400 = 1 day)
history_bucket_sec=86400

# Cross-network trading policy
cross_net_policy=reject

# Extended debug logging (default: true)
debug_more=true
```

---

## Configuration Parameters

### memcached

| Value | Description |
|-------|-------------|
| `true` | Enable hot order cache (faster matching) |
| `false` | All queries hit ledger (slower, no extra memory) |

**Default:** `false`

**Impact:**
- `true`: O(1) order lookups, sorted pair buckets
- `false`: O(n) ledger scans per query

---

### history_cache

| Value | Description |
|-------|-------------|
| `true` | Enable OHLCV aggregation |
| `false` | No historical analytics |

**Default:** `false`

**Commands affected:**
- `srv_dex history -mode volume`
- `srv_dex history -mode ohlc`
- `srv_dex history -mode trades`

---

### history_bucket_sec

Storage bucket size for trade indexing (lite bucket architecture).

| Value | Description |
|-------|-------------|
| `3600` | Hourly buckets |
| `86400` | Daily buckets (default, recommended) |

**Note:** This controls storage granularity. OHLCV candles are computed on-the-fly at query time, so you can request any candle size (e.g., 1-minute, 5-minute) regardless of this setting. Larger bucket sizes reduce memory overhead.

---

### cross_net_policy

Controls cross-network token pair trading.

| Value | Behavior |
|-------|----------|
| `reject` | Block cross-net pairs (default) |
| `warn` | Allow with log warning |
| `allow` | Allow silently |

**Note:** This is a soft control outside consensus. Pairs must still be whitelisted via decree.

---

### debug_more

| Value | Description |
|-------|-------------|
| `true` | Extended debug logging (verificator, matching) |
| `false` | Normal logging |

**Default:** `true`

---

## Governance via Decree

All runtime DEX configuration is managed through on-chain decrees. This ensures:
- Consensus-validated changes
- Audit trail
- No trusted operator required

---

## Decree TSD Types

```c
#define DEX_DECREE_TSD_METHOD      0x0000  // uint8_t decree method
#define DEX_DECREE_TSD_TOKEN_BASE  0x0001
#define DEX_DECREE_TSD_TOKEN_QUOTE 0x0002
#define DEX_DECREE_TSD_NET_BASE    0x0003
#define DEX_DECREE_TSD_NET_QUOTE   0x0004
#define DEX_DECREE_TSD_FEE_CONFIG  0x0005
#define DEX_DECREE_TSD_FEE_AMOUNT  0x0020  // uint256_t
#define DEX_DECREE_TSD_FEE_ADDR    0x0021  // dap_chain_addr_t
```

---

## Decree Methods

```c
typedef enum {
    DEX_DECREE_FEE_SET = 1,
    DEX_DECREE_PAIR_ADD = 2,
    DEX_DECREE_PAIR_REMOVE = 3,
    DEX_DECREE_PAIR_FEE_SET = 4,
    DEX_DECREE_PAIR_FEE_SET_ALL = 5
} dex_decree_method_t;
```

---

## Method: FEE_SET

Sets global native fee fallback and service wallet address.

### Required TSD
| Type | Content |
|------|---------|
| `METHOD` | `1` |
| `FEE_AMOUNT` | `uint256_t` — native fee amount |
| `FEE_ADDR` | `dap_chain_addr_t` — service wallet |

### Prohibited TSD
- `TOKEN_BASE`, `TOKEN_QUOTE`
- `NET_BASE`, `NET_QUOTE`
- `FEE_CONFIG`

### Effect
```c
s_dex_native_fee_amount = <FEE_AMOUNT>;
s_dex_service_fee_addr = <FEE_ADDR>;
```

### CLI
```bash
srv_dex decree -net TestNet -w admin.dwallet -service_key dex_admin \
  -method fee_set -fee_amount 0.05 -fee_addr Ax7y9q...
```

---

## Method: PAIR_ADD

Adds new trading pair to whitelist.

### Required TSD
| Type | Content |
|------|---------|
| `METHOD` | `2` |
| `TOKEN_BASE` | Base token ticker |
| `TOKEN_QUOTE` | Quote token ticker |
| `NET_BASE` | Network ID for base token |
| `NET_QUOTE` | Network ID for quote token |

### Optional TSD
| Type | Content |
|------|---------|
| `FEE_CONFIG` | Per-pair fee configuration |

### Prohibited TSD
- `FEE_AMOUNT`, `FEE_ADDR`

### Effect
```c
dex_pair_key_t l_key = { .token_base = <TOKEN_BASE>, ... };
l_key.fee_config = <FEE_CONFIG> or 0;
s_dex_pair_index_add(&l_key);
```

### CLI
```bash
srv_dex decree -net TestNet -w admin.dwallet -service_key dex_admin \
  -method pair_add -token_base KEL -token_quote USDT -fee_pct 2.0
```

---

## Method: PAIR_REMOVE

Removes trading pair from whitelist.

### Required TSD
| Type | Content |
|------|---------|
| `METHOD` | `3` |
| `TOKEN_BASE` | Base token ticker |
| `TOKEN_QUOTE` | Quote token ticker |
| `NET_BASE` | Network ID for base token |
| `NET_QUOTE` | Network ID for quote token |

### Prohibited TSD
- `FEE_CONFIG`, `FEE_AMOUNT`, `FEE_ADDR`

### Effect
```c
s_dex_pair_index_remove(&l_key);
// All orders of this pair are removed from cache
```

### CLI
```bash
srv_dex decree -net TestNet -w admin.dwallet -service_key dex_admin \
  -method pair_remove -token_base KEL -token_quote USDT
```

**Warning:** Removes all cached orders for this pair!

---

## Method: PAIR_FEE_SET

Updates fee configuration for specific pair.

### Required TSD
| Type | Content |
|------|---------|
| `METHOD` | `4` |
| `TOKEN_BASE` | Base token ticker |
| `TOKEN_QUOTE` | Quote token ticker |
| `NET_BASE` | Network ID for base token |
| `NET_QUOTE` | Network ID for quote token |
| `FEE_CONFIG` | New fee configuration byte |

### Prohibited TSD
- `FEE_AMOUNT`, `FEE_ADDR`

### Effect
```c
l_pair->key.fee_config = <FEE_CONFIG>;
```

### CLI
```bash
srv_dex decree -net TestNet -w admin.dwallet -service_key dex_admin \
  -method pair_fee_set -token_base KEL -token_quote USDT -fee_pct 1.5
```

---

## Method: PAIR_FEE_SET_ALL

Updates fee configuration for ALL pairs.

### Required TSD
| Type | Content |
|------|---------|
| `METHOD` | `5` |
| `FEE_CONFIG` | New fee configuration byte |

### Prohibited TSD
- `TOKEN_BASE`, `TOKEN_QUOTE`
- `NET_BASE`, `NET_QUOTE`
- `FEE_AMOUNT`, `FEE_ADDR`

### Effect
```c
HASH_ITER(hh, s_dex_pair_index, l_it, l_tmp) {
    l_it->key.fee_config = <FEE_CONFIG>;
}
```

### CLI
```bash
srv_dex decree -net TestNet -w admin.dwallet -service_key dex_admin \
  -method pair_fee_set_all -fee_pct 2.0
```

---

## Fee Configuration Encoding

### CLI Fee Options

| Option | Encoding |
|--------|----------|
| `-fee_pct 2.0` | `0x94` (percent mode, 20 = 2.0%) |
| `-fee_native 0.05` | `0x05` (native mode, 5 units) |
| `-fee_config 0x94` | Direct byte value |

### Conversion Examples

**Percent to Byte:**
```
fee_pct 1.5% → 15 (0.1% steps) → 0x80 | 15 = 0x8F
fee_pct 10% → 100 (0.1% steps) → 0x80 | 100 = 0xE4
```

**Native to Byte:**
```
fee_native 0.05 → 5 (0.01 steps) → 0x05
fee_native 1.27 → 127 (max) → 0x7F
```

---

## Service Key Requirements

Decrees must be signed with a service key that has authority over the DEX service.

### Key Registration

```bash
# Create service certificate
cellframe-node-tool cert create dex_admin sig_dil
```

### Key Usage

```bash
srv_dex decree ... -service_key dex_admin
```

---

## State Persistence

### Runtime State

Decree-applied state is held in memory:
- `s_dex_native_fee_amount`
- `s_dex_service_fee_addr`
- `s_dex_pair_index` (with fee_config per pair)

### Persistence

State is reconstructed on node restart by replaying all relevant decrees from the chain.

---

## Initialization Sequence

```c
int dap_chain_net_srv_dex_init() {
    // 1. Read config
    s_debug_more = dap_config_get_item_bool_default(...);
    s_cross_net_policy = ...;
    s_dex_cache_enabled = ...;
    s_dex_history_enabled = ...;
    s_dex_history_bucket_sec = ...;

    // 2. Register verificator
    dap_ledger_verificator_add(DAP_CHAIN_TX_OUT_COND_SUBTYPE_SRV_DEX, ...);

    // 3. Subscribe to decree callbacks
    for (each network) {
        dap_ledger_srv_callback_decree_add(ledger, DEX_SRV_UID, callback);
        if (cache_enabled || history_enabled)
            dap_ledger_tx_add_notify(ledger, notify_callback, NULL);
    }

    // 4. Register CLI
    dap_cli_server_cmd_add("srv_dex", ...);
}
```

---

## Runtime Updates

Decree callbacks execute atomically under write lock:

```c
int dap_chain_net_srv_dex_decree_callback(...) {
    // Validation
    // ...

    if (a_apply) {
        pthread_rwlock_wrlock(&s_dex_cache_rwlock);
        // Apply changes
        pthread_rwlock_unlock(&s_dex_cache_rwlock);
    }
}
```

**Note:** Validation runs first (without lock) to fail fast on invalid decrees.



