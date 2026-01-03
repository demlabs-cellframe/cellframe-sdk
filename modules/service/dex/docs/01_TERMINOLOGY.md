# DEX v2 Terminology

## Trading Pair

```
BASE / QUOTE
```

| Token | Description |
|-------|-------------|
| **BASE** | Primary asset (e.g., KEL in KEL/USDT) |
| **QUOTE** | Pricing asset (e.g., USDT in KEL/USDT) |

Canonical pair order: token with smaller ticker < token with larger ticker (lexicographic).

---

## Price (Rate)

All prices stored in **canonical QUOTE/BASE** format:

```
rate = QUOTE_amount / BASE_amount
```

Example: 1 KEL = 2.5 USDT → rate = 2.5

---

## Order Sides

| Side | Seller Sells | Seller Receives | Canonical Price |
|------|--------------|-----------------|-----------------|
| **ASK** | BASE | QUOTE | QUOTE/BASE (direct) |
| **BID** | QUOTE | BASE | QUOTE/BASE (inverted storage) |

```c
#define DEX_SIDE_ASK 0  // Seller sells BASE
#define DEX_SIDE_BID 1  // Seller sells QUOTE
```

**Buyer perspective:**
- ASK = buyer pays QUOTE, receives BASE
- BID = buyer pays BASE, receives QUOTE

---

## Transaction Types

```c
typedef enum dex_tx_type {
    DEX_TX_TYPE_UNDEFINED,
    DEX_TX_TYPE_ORDER,      // New order creation
    DEX_TX_TYPE_EXCHANGE,   // Trade execution (partial or full)
    DEX_TX_TYPE_UPDATE,     // Owner value modification
    DEX_TX_TYPE_INVALIDATE  // Order cancellation
} dex_tx_type_t;
```

| Type | IN_COND | SRV_DEX OUT | Description |
|------|---------|-------------|-------------|
| ORDER | 0 | Yes (root=blank) | Create new order |
| EXCHANGE | 1+ | Optional (residual) | Execute trade(s) |
| UPDATE | 1 | Yes (root=set) | Owner modifies value |
| INVALIDATE | 1+ | No | Cancel order(s) |

---

## Order State

### Root vs Tail

| Hash | Description |
|------|-------------|
| **Root** | First TX in order chain (immutable identifier) |
| **Tail** | Current head of chain (changes with each trade/update) |

```
ORDER (root=tail) → EXCHANGE (new tail) → EXCHANGE (new tail) → INVALIDATE
```

### Order Chain

Linked sequence of transactions forming order lifecycle:

```
root_tx ←── trade_tx_1 ←── trade_tx_2 ←── ... ←── tail_tx
```

Each TX references previous via `order_root_hash` field.

---

## Fill Policies

```c
uint8_t min_fill;  // [bit7: from_origin] [bits0-6: percent]
```

| Policy | min_fill | Meaning |
|--------|----------|---------|
| PARTIAL_OK | 0x00 | Any fill accepted |
| MIN 50% | 0x32 | At least 50% of remaining |
| MIN 50% (origin) | 0xB2 | At least 50% of original value |
| AON | 0x64 | 100% required (All-Or-Nothing) |

### from_origin Flag

| bit7 | Calculation Base |
|------|------------------|
| 0 | Percentage of current remaining value |
| 1 | Percentage of original order value |

---

## Trade Classification

```c
#define DEX_TRADE_FLAG_MARKET   0x01  // Best price execution
#define DEX_TRADE_FLAG_TARGETED 0x02  // Specific order purchase
#define DEX_TRADE_FLAG_ORDER    0x04  // Order creation event
```

| Flag | Description |
|------|-------------|
| MARKET | Trade at or better than best available price |
| TARGETED | Direct purchase of specific order |
| ORDER | Not a trade; order placement record |

---

## Residual vs Leftover

| Term | Creator | Description |
|------|---------|-------------|
| **Seller Residual** | Seller (partial fill) | Remaining order value after partial trade |
| **Buyer Leftover** | Buyer (unspent budget) | New order from excess buyer funds |

Both are SRV_DEX OUT_COND but serve different purposes:
- Residual continues existing order chain
- Leftover starts new order chain

---

## Pair Key

```c
typedef struct dex_pair_key {
    dap_chain_net_id_t net_id_base, net_id_quote;
    char token_base[DAP_CHAIN_TICKER_SIZE_MAX];
    char token_quote[DAP_CHAIN_TICKER_SIZE_MAX];
    uint8_t fee_config;
} dex_pair_key_t;
```

Hash key size excludes `fee_config`:

```c
#define DEX_PAIR_KEY_CMP_SIZE offsetof(dex_pair_key_t, fee_config)
```

---

## Budget Types

| is_budget_buy | Budget Token | Meaning |
|---------------|--------------|---------|
| `true` | Buy token | "I want to receive X tokens" |
| `false` | Sell token | "I want to spend X tokens" |

---

## Executed Amount

Volume traded in a single TX:

```c
executed = prev_value - residual_value  // Partial fill
executed = prev_value                    // Full fill
```

For BID orders, conversion to BASE units:

```c
exec_base = exec_quote / rate
```

---

## Dust

Minimum viable order amount. Orders below dust threshold:
- Cannot be partially filled
- Treated as AON
- May trigger refund on full execution

---

## OHLCV

| Field | Description |
|-------|-------------|
| O | Open price (first trade in bucket) |
| H | High price (maximum in bucket) |
| L | Low price (minimum in bucket) |
| C | Close price (last trade in bucket) |
| V | Volume (sum of traded amounts) |

Computed from MARKET trades only. TARGETED trades contribute to volume but not OHLC.

---

## Bucket

Time interval for OHLCV aggregation:

```c
uint64_t bucket_ts = (timestamp / bucket_size) * bucket_size;
```

Standard sizes: 60 (1m), 300 (5m), 900 (15m), 3600 (1h), 86400 (1d).

---

## Service ID

```c
#define DAP_CHAIN_NET_SRV_DEX_ID 0x000000000000000AULL
```

Subtype code:

```c
#define DAP_CHAIN_TX_OUT_COND_SUBTYPE_SRV_DEX 0x05
```

---

## OUT_COND Payload

```c
struct srv_dex {
    dap_chain_net_id_t buy_net_id, sell_net_id;
    char buy_token[DAP_CHAIN_TICKER_SIZE_MAX];
    dap_chain_addr_t seller_addr;
    dap_chain_hash_fast_t order_root_hash;  // Blank for ORDER
    uint256_t rate;                          // Canonical QUOTE/BASE
    uint8_t min_fill;                        // Fill policy
    uint8_t version;                         // Payload version
    uint32_t flags;                          // Reserved
    uint8_t tx_type;                         // ORDER/EXCHANGE/UPDATE
} DAP_ALIGN_PACKED;
```

---

## side_version Encoding

Combined field in cache entries:

```c
uint8_t side_version;
// bit 0:    side (0=ASK, 1=BID)
// bits 1-7: version from OUT_COND

uint8_t side = side_version & 0x1;
uint8_t version = (side_version >> 1) & 0x7F;
```


