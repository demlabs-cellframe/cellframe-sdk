# DEX v2 CLI Reference

## Command Structure

```
srv_dex <subcommand> [options]
```

---

## Order Management

### Create Order

```bash
srv_dex order create \
  -net <network_name> \
  -token_sell <ticker> \
  -token_buy <ticker> \
  -w <wallet_path> \
  -value <amount> \
  -rate <price> \
  -fee <validator_fee> \
  [-fill_policy <policy>] \
  [-min_fill_pct <0-100>] \
  [-min_fill_value <amount>]
```

**Parameters:**
| Parameter | Description |
|-----------|-------------|
| `-net` | Network name |
| `-token_sell` | Token to sell |
| `-token_buy` | Token to receive |
| `-w` | Wallet file path |
| `-value` | Amount to sell |
| `-rate` | Price in canonical QUOTE/BASE (QUOTE per 1 BASE) |
| `-fee` | Validator fee in native |
| `-fill_policy` | `AON`, `min`, or `min_from_origin` |
| `-min_fill_pct` | Percentage for min policies (0-100) |
| `-min_fill_value` | Absolute minimum fill in sell token (auto-sets `min_from_origin`) |

**Notes:**
- `-min_fill_pct` and `-min_fill_value` are mutually exclusive
- `-min_fill_value` auto-computes percentage from `-value` and sets `min_from_origin` policy
- If `-min_fill_value` >= `-value`, order becomes AON (100%)

**Example:**
```bash
srv_dex order create -net TestNet -token_sell KEL -token_buy USDT \
  -w /home/user/.cellframe/wallets/bob.dwallet -value 100.0 -rate 2.5 -fee 0.05

# BID example (sell QUOTE, buy BASE; rate still QUOTE/BASE):
srv_dex order create -net TestNet -token_sell USDT -token_buy KEL \
  -w /home/user/.cellframe/wallets/bob.dwallet -value 250.0 -rate 2.5 -fee 0.05

# With absolute min_fill (at least 50 KEL must be filled):
srv_dex order create -net TestNet -token_sell KEL -token_buy USDT \
  -w /home/user/.cellframe/wallets/bob.dwallet -value 100.0 -rate 2.5 -fee 0.05 \
  -min_fill_value 50.0
```

---

### Remove Order (Invalidate)

```bash
srv_dex order remove \
  -net <network_name> \
  -order <order_hash> \
  -w <wallet_path> \
  -fee <validator_fee>
```

**Example:**
```bash
srv_dex order remove -net TestNet \
  -order 0x1234...abcd \
  -w /home/user/.cellframe/wallets/bob.dwallet \
  -fee 0.05
```

---

### Update Order

```bash
srv_dex order update \
  -net <network_name> \
  -order <root_hash> \
  -w <wallet_path> \
  -value <new_value> \
  -fee <validator_fee>
```

**Note:** Only the order owner can update. Updates the locked value (increase or decrease).

---

## Purchase Operations

### Single Order Purchase

Execute trade against a single order. Buyer pays in the order's buy token and receives the sell token.

```bash
srv_dex purchase \
  -net <network_name> \
  -order <order_hash> \
  -w <wallet_path> \
  -value <amount> \
  [-unit sell|buy] \
  -fee <validator_fee> \
  [-create_leftover_order] \
  [-leftover_rate <rate>]
```

**Parameters:**
| Parameter | Required | Description |
|-----------|----------|-------------|
| `-net` | Yes | Network name |
| `-order` | Yes | Order hash to purchase against |
| `-w` | Yes | Wallet file path |
| `-value` | Yes | Budget amount (`0` = unlimited) |
| `-fee` | Yes | Validator fee in native token |
| `-unit` | No | Budget denomination: `sell` (default) or `buy` |
| `-create_leftover_order` | No | Create order from unspent budget |
| `-leftover_rate` | Conditional | Rate for leftover order in canonical QUOTE/BASE (required if `-create_leftover_order` is set) |

**Example:**
```bash
srv_dex purchase -net TestNet \
  -order 0x1234...abcd \
  -w /home/user/.cellframe/wallets/alice.dwallet \
  -value 50.0 -unit buy -fee 0.05

# With leftover order (rate in canonical QUOTE/BASE):
srv_dex purchase -net TestNet \
  -order 0x1234...abcd \
  -w /home/user/.cellframe/wallets/alice.dwallet \
  -value 50.0 -unit sell -fee 0.05 \
  -create_leftover_order -leftover_rate 2.3
```

---

### Multi-Order Purchase

Execute trade against multiple orders in a single transaction. Orders are processed in the provided order and the transaction is atomic.

```bash
srv_dex purchase_multi \
  -net <network_name> \
  -orders <hash1,hash2,...> \
  -w <wallet_path> \
  -value <amount> \
  -fee <validator_fee> \
  [-unit sell|buy] \
  [-create_leftover_order] \
  [-leftover_rate <rate>]
```

**Parameters:**
| Parameter | Required | Description |
|-----------|----------|-------------|
| `-net` | Yes | Network name |
| `-orders` | Yes | Comma-separated list of order hashes |
| `-w` | Yes | Wallet file path |
| `-value` | Yes | Budget amount |
| `-fee` | Yes | Validator fee in native token |
| `-unit` | No | Budget denomination: `sell` (default) or `buy` |
| `-create_leftover_order` | No | Create order from unspent budget |
| `-leftover_rate` | Conditional | Rate for leftover order in canonical QUOTE/BASE (required if `-create_leftover_order`; forbidden otherwise) |

**Example:**
```bash
srv_dex purchase_multi -net TestNet \
  -orders 0x111...aaa,0x222...bbb,0x333...ccc \
  -w /home/user/.cellframe/wallets/alice.dwallet \
  -value 100.0 -unit sell -fee 0.05

# With leftover order (rate in canonical QUOTE/BASE):
srv_dex purchase_multi -net TestNet \
  -orders 0x111...aaa,0x222...bbb,0x333...ccc \
  -w /home/user/.cellframe/wallets/alice.dwallet \
  -value 80.0 -unit buy -fee 0.05 \
  -create_leftover_order -leftover_rate 2.1
```

---

### Auto-Match Purchase

Automatic matching by best price for the given pair; supports dry-run simulation.

```bash
srv_dex purchase_auto \
  -net <network_name> \
  -token_sell <ticker> \
  -token_buy <ticker> \
  -w <wallet_path> \
  -value <amount> \
  [-unit sell|buy] \
  [-rate_cap <rate>] \
  -fee <validator_fee> \
  [-create_leftover_order] \
  [-leftover_rate <rate>] \
  [-dry-run]
```

**Parameters:**
| Parameter | Required | Description |
|-----------|----------|-------------|
| `-net` | Yes | Network name |
| `-token_sell` | Yes | Token to sell (spend) |
| `-token_buy` | Yes | Token to buy (receive) |
| `-w` | Yes | Wallet file path |
| `-value` | Yes | Budget amount (`0` = unlimited) |
| `-fee` | Yes | Validator fee in native token |
| `-unit` | No | Budget denomination: `sell` (default) or `buy` |
| `-rate_cap` | No | Price limit in canonical QUOTE/BASE: BID skips rate > cap, ASK skips rate < cap |
| `-create_leftover_order` | No | Create order from unspent budget |
| `-leftover_rate` | Conditional | Rate for leftover order in canonical QUOTE/BASE (required if `-create_leftover_order`; forbidden otherwise) |
| `-dry-run` | No | Simulate matching without submitting TX (returns match plan in JSON) |

**Notes:**
- `-fee` is required even in `-dry-run` mode (validation requires non-zero fee).

**Example:**
```bash
srv_dex purchase_auto -net TestNet \
  -token_sell USDT -token_buy KEL \
  -w /home/user/.cellframe/wallets/alice.dwallet \
  -value 50.0 -unit buy -rate_cap 2.0 -fee 0.05

# ASK example (sell BASE, buy QUOTE; rate_cap still QUOTE/BASE):
srv_dex purchase_auto -net TestNet \
  -token_sell KEL -token_buy USDT \
  -w /home/user/.cellframe/wallets/alice.dwallet \
  -value 50.0 -unit sell -rate_cap 2.5 -fee 0.05

# Dry-run example
srv_dex purchase_auto -net TestNet \
  -token_sell USDT -token_buy KEL \
  -w /home/user/.cellframe/wallets/alice.dwallet \
  -value 50.0 -fee 0.05 -dry-run

# With leftover order (rate in canonical QUOTE/BASE):
srv_dex purchase_auto -net TestNet \
  -token_sell USDT -token_buy KEL \
  -w /home/user/.cellframe/wallets/alice.dwallet \
  -value 50.0 -unit sell -fee 0.05 \
  -create_leftover_order -leftover_rate 2.2
```

---

### Bulk Cancel

```bash
srv_dex cancel_all_by_seller \
  -net <network_name> \
  -pair <BASE/QUOTE> \
  -seller <address> \
  -w <wallet_path> \
  -fee <validator_fee> \
  [-limit <N>] \
  [-dry-run]
```

**Parameters:**
| Parameter | Required | Description |
|-----------|----------|-------------|
| `-net` | Yes | Network name |
| `-pair` | Yes | Canonical pair (e.g., `KEL/USDT`) |
| `-seller` | Yes | Seller address (must match wallet) |
| `-w` | Yes | Wallet file path |
| `-fee` | Yes | Validator fee in native token |
| `-limit` | No | Maximum orders to cancel (default: unlimited) |
| `-dry-run` | No | Report candidates only, don't create TX |

**Example:**
```bash
srv_dex cancel_all_by_seller -net TestNet \
  -pair KEL/USDT \
  -seller Ax7y9q... \
  -w /home/user/.cellframe/wallets/bob.dwallet \
  -fee 0.05 -limit 10 -dry-run
```

---

## Query Operations

### List Orders

```bash
srv_dex orders \
  -net <network_name> \
  [-pair <BASE/QUOTE>] \
  [-seller <address>] \
  [-limit <N>] \
  [-offset <N>]
```

**Parameters:**
| Parameter | Description |
|-----------|-------------|
| `-pair` | Filter by trading pair (optional; omit to list all pairs) |
| `-seller` | Filter by seller address |
| `-limit` | Maximum orders to return |
| `-offset` | Skip first N orders |

**Note:** When `-pair` is omitted, each order includes a `pair` field in the output.

**Example:**
```bash
srv_dex orders -net TestNet -pair KEL/USDT
srv_dex orders -net TestNet -seller Ax7y9q... -limit 100 -offset 0
srv_dex orders -net TestNet  # All orders across all pairs
```

---

### Order Book

```bash
srv_dex orderbook \
  -net <network_name> \
  -pair <BASE/QUOTE> \
  [-depth <N>] \
  [-tick_price <decimals>] \
  [-tick <decimals>] \
  [-cumulative]
```

**Parameters:**
| Parameter | Description |
|-----------|-------------|
| `-depth` | Number of price levels (default: 20, max: 1000) |
| `-tick_price` | Explicit price step for level aggregation (value, not decimals) |
| `-tick` | Decimal places to derive price step (e.g., 2 → step 0.01) |
| `-cumulative` | Show cumulative volumes |

**Example:**
```bash
srv_dex orderbook -net TestNet -pair KEL/USDT -depth 10 -cumulative
```

Output: Top N ASK and BID levels with price, volume_base/volume_quote, and order count (plus cumulative fields if requested).

---

### Market Status

```bash
srv_dex status \
  -net <network_name> \
  -pair <BASE/QUOTE> \
  [-seller <address>]
```

Returns: Order counts and best prices (best_ask, best_bid, mid, spread).

---

### List Pairs

```bash
srv_dex pairs -net <network_name>
```

Lists all whitelisted trading pairs with fee configurations.

---

## Analytics

### market_rate

Calculate volume-weighted average price (VWAP) for a period.

```bash
srv_dex market_rate \
  -net <network_name> \
  -pair <BASE/QUOTE> \
  [-from <timestamp>] \
  [-to <timestamp>] \
  [-bucket <seconds>]
```

Example:
```bash
srv_dex market_rate -net Backbone -pair KEL/USDT -from 1700000000 -to 1700100000 -bucket 3600
```

### volume

Trading volume for a period (optionally bucketed).

```bash
srv_dex volume \
  -net <network_name> \
  -pair <BASE/QUOTE> \
  [-from <timestamp>] \
  [-to <timestamp>] \
  [-bucket <seconds>]
```

### Spread

```bash
srv_dex spread \
  -net <network_name> \
  -pair <BASE/QUOTE> \
  [-verbose]
```

Returns: Best ASK, best BID, spread percentage.

---

### TVL (Total Value Locked)

```bash
srv_dex tvl \
  -net <network_name> \
  [-token <ticker>] \
  [-by pair] \
  [-top <N>]
```

**Parameters:**
| Parameter | Description |
|-----------|-------------|
| `-token` | Filter by specific token |
| `-by pair` | Group results by trading pair |
| `-top` | Show top N pairs by TVL |

Returns: Total amount of token(s) locked in active orders.

---

### Slippage Estimation

```bash
srv_dex slippage \
  -net <network_name> \
  -pair <BASE/QUOTE> \
  -value <amount> \
  -side buy|sell \
  -unit base|quote \
  [-max_slippage_pct <percent>]
```

**Parameters:**
| Parameter | Description |
|-----------|-------------|
| `-max_slippage_pct` | Maximum acceptable slippage (0-100) |

**Example:**
```bash
srv_dex slippage -net TestNet -pair KEL/USDT -value 1000 -side buy -unit quote -max_slippage_pct 5
```

---

### Find Matches

```bash
srv_dex find_matches \
  -net <network_name> \
  -order <hash> \
  -addr <wallet_addr>
```

Analyzes potential counter-matches for a legacy or DEX order.  
Matches owned by the provided address are excluded.

**Parameters:**
| Parameter | Description |
|-----------|-------------|
| `-order` | Order hash (any hash in legacy/DEX order chain; resolved to current tail) |
| `-addr` | Wallet address used to skip self-matches |

**Output fields:**
| Field | Description |
|-------|-------------|
| `order_hash` | Input hash as provided |
| `order_tail` | Resolved tail hash if input is not the tail |
| `legacy` | `true` for legacy XCHANGE orders |
| `pair` | Canonical pair `BASE/QUOTE` |
| `side` | Analyzed order side: `ask` or `bid` |
| `rate` | Order rate (canonical QUOTE/BASE) |
| `budget` | Remaining value of the analyzed order |
| `budget_token` | Token of `budget` (always analyzed order sell token) |
| `addr_matches_owner` | `true` if `-addr` matches order owner |
| `warning` | Optional warning string (e.g., `addr_not_owner`) |
| `matches_count` | Number of matching orders |
| `matches[]` | Array of match objects |
| `matches[].root` | Matched order root hash |
| `matches[].tail` | Matched order tail hash |
| `matches[].rate` | Matched order rate (canonical QUOTE/BASE) |
| `matches[].spend` | Amount and token the analyzed order pays |
| `matches[].receive` | Amount and token the analyzed order receives |

**Example:**
```bash
srv_dex find_matches -net TestNet \
  -order 0x6B84...A770 \
  -addr Ax7y9q...
```

```json
{
  "order_hash": "0x6B84...A770",
  "order_tail": "0xB6C2...8F4B",
  "legacy": true,
  "pair": "KEL/USDT",
  "side": "ask",
  "rate": "2.5",
  "budget": "100",
  "budget_token": "KEL",
  "addr_matches_owner": true,
  "matches_count": 2,
  "matches": [
    {
      "root": "0x1111...1111",
      "tail": "0x2222...2222",
      "rate": "2.5",
      "spend": "18 KEL",
      "receive": "45 USDT"
    },
    {
      "root": "0x3333...3333",
      "tail": "0x4444...4444",
      "rate": "2.48",
      "spend": "16 KEL",
      "receive": "40 USDT"
    }
  ]
}
```

---

### Trade History

```bash
srv_dex history \
  -net <network_name> \
  [-pair <BASE/QUOTE> | -order <hash>] \
  [-from <timestamp>] \
  [-to <timestamp>] \
  [-view events|summary|ohlc|volume] \
  [-type all|trade|market|targeted|order|update|cancel] \
  [-bucket <seconds>] \
  [-seller <address>] \
  [-buyer <address>] \
  [-fill] \
  [-limit <N>] \
  [-offset <N>]
```

**Parameters:**
| Parameter | Description |
|-----------|-------------|
| `-pair` | Trading pair `BASE/QUOTE` (alternative to `-order`) |
| `-view` | Output format: `events` (default), `summary`, `ohlc`, `volume` |
| `-type` | Event filter: `all`, `trade`, `market`, `targeted`, `order`, `update`, `cancel` |
| `-bucket` | Bucket size in seconds (optional for ohlc/volume; omit to get totals only) |
| `-fill` | Fill empty buckets with previous close (uses `history_bucket_sec` when `-bucket` is omitted) |
| `-seller` | Filter by seller address |
| `-buyer` | Filter by buyer address |
| `-limit` | Maximum records to return (`events`/`summary` only) |
| `-offset` | Skip first N records (`events`/`summary` only) |
| `-order` | Filter by specific order hash (root or tail); pair is derived from order |

**Format Compatibility:**
| Format | Valid Parameters | Invalid Parameters |
|--------|------------------|-------------------|
| `events` | `-from`, `-to`, `-seller`, `-buyer`, `-order`, `-type`, `-limit`, `-offset` | `-bucket`, `-fill` |
| `summary` | `-seller`, `-order`, `-type`, `-limit`, `-offset` | `-bucket`, `-fill` |
| `ohlc` | `-bucket`, `-fill`, `-from`, `-to`, `-seller`, `-buyer`, `-order`, `-type` | `-limit`, `-offset` |
| `volume` | `-bucket`, `-fill`, `-from`, `-to`, `-seller`, `-buyer`, `-order`, `-type` | `-limit`, `-offset` |

**Type Compatibility (for `ohlc`/`volume`):**
| Type | `ohlc` | `volume` |
|------|--------|----------|
| `trade` | ✅ | ✅ |
| `market` | ✅ | ✅ |
| `targeted` | ❌ | ✅ |
| `order` / `update` / `cancel` / `all` | ❌ | ❌ |

**Notes:**
- `-fill` uses `history_bucket_sec` when `-bucket` is omitted (fills empty buckets with previous close price)
- `-order` resolves the provided hash to `order_root` and matches trades by their order chain root
- If `-pair` is omitted, the pair is resolved from the order hash (cache or ledger)
- `-buyer` can be combined with `-order` to filter events by counterparty
- For `ohlc`/`volume`, aggregation uses trade events only (`MARKET|TARGETED`); OHLC prices use `MARKET` only
- When `history_cache=false`, results are computed from ledger scan: `market_only=false`, and bucket entries include `first_ts`/`last_ts`
- When `history_cache=false`, `market` vs `targeted` trades are not distinguishable (both treated as `trade`)
- `-type` defaults to `all` for `events`, to `market` for `ohlc`, and to `trade` for `volume`
- `summary` format returns per-order last event and ignores `-from`/`-to`
- `events` and `summary` formats require both `history_cache=true` and `cache_enabled=true`

**Format Requirements:**
| Format | Requirements |
|--------|--------------|
| `ohlc` | None (bucket optional) |
| `volume` | None (bucket optional) |
| `events` | `history_cache=true` and `cache_enabled=true` |
| `summary` | `history_cache=true` and `cache_enabled=true` |

---

#### Format: Events (default)

Default `-type` is `all`.

Returns all recorded events without type filtering.

```bash
srv_dex history -net TestNet -pair KEL/USDT
```

```json
{
  "pair": "KEL/USDT",
  "events": [...],
  "count": 123
}
```

---

#### Format: Summary

Returns one record per order with its last event and execution percent.

```bash
srv_dex history -net TestNet -pair KEL/USDT -view summary -limit 10
```

```json
{
  "pair": "KEL/USDT",
  "summary": [...],
  "count": 10
}
```

Notes:

- `spent` and `received` include the token ticker in the same string (for example, `100.0 KEL`).
- `remained` is included for partially filled orders and shows remaining locked amount with its ticker.

---

#### Totals Only (no bucket)

When `-bucket` is omitted, returns only aggregate totals without time series:

```bash
srv_dex history -net TestNet -pair KEL/USDT -view ohlc -from -7d
```

```json
{
  "pair": "KEL/USDT",
  "request_ts": 1703847123,
  "market_only": true,
  "ohlc": [],
  "totals": {
    "trades": 623,
    "sum_base": "35000.861",
    "sum_quote": "280006.888",
    "spot": "8.0123",
    "vwap": "8.0002"
  }
}
```

---

#### Format: OHLC

Default `-type` is `market`.

Returns OHLC candlestick data with volume and trade count per bucket.

```bash
srv_dex history -net TestNet -pair KEL/USDT -view ohlc -bucket 3600 -fill -from -24h
```

```json
{
  "pair": "KEL/USDT",
  "market_only": true,
  "ohlc": [
    {
      "ts": 1703800800,
      "ts_str": "Thu, 28 Dec 2023 22:00:00 GMT",
      "open": "8.0100",
      "high": "8.0500",
      "low": "7.9800",
      "close": "8.0200",
      "volume_base": "1234.5678",
      "volume_quote": "9876.5432",
      "trades": 42
    }
  ],
  "count": 24,
  "totals": {
    "trades": 150,
    "sum_base": "12345.678",
    "sum_quote": "98765.432",
    "spot": "8.0123",
    "vwap": "8.0005"
  }
}
```

---

#### Format: Volume

Default `-type` is `trade`.

Returns only volume data per bucket (no OHLC prices).

```bash
srv_dex history -net TestNet -pair KEL/USDT -view volume -bucket 86400 -from -7d
```

```json
{
  "pair": "KEL/USDT",
  "market_only": true,
  "volume": [
    {
      "ts": 1703721600,
      "ts_str": "Thu, 28 Dec 2023 00:00:00 GMT",
      "volume_base": "5000.123",
      "volume_quote": "40000.984",
      "trades": 89
    }
  ],
  "count": 7,
  "totals": {
    "trades": 623,
    "sum_base": "35000.861",
    "sum_quote": "280006.888",
    "spot": "8.0123",
    "vwap": "8.0002"
  }
}
```

---

#### Format: Events (trades)

Returns raw trade records in events format. Requires both `history_cache=true` and `cache_enabled=true`.

```bash
srv_dex history -net TestNet -pair KEL/USDT -view events -type trade -limit 10
```

```json
{
  "pair": "KEL/USDT",
  "trades": [
    {
      "ts": 1703847123,
      "ts_str": "Fri, 29 Dec 2023 10:52:03 GMT",
      "price": "8.0150",
      "base": "100.0",
      "quote": "801.50",
      "tx_hash": "0x1234...abcd",
      "prev_tail": "0x5678...efgh",
      "order_root": "0x9abc...def0",
      "filled_pct": 12,
      "seller": "mJUaYn...",
      "buyer": "mZkPqR...",
      "type": "market"
    }
  ],
  "count": 10
}
```

**Trade types:**
- `market` — executed at or better than best price
- `targeted` — executed at worse than best price (limit order match)

---

#### Events: Orders (order creations only)

Returns only order creation records (new orders and buyer leftovers).
Buyer leftovers may be marked as `order+market` or `order+targeted` depending on the last trade classification.

```bash
srv_dex history -net TestNet -pair KEL/USDT -view events -type order -limit 10
```

```json
{
  "pair": "KEL/USDT",
  "orders": [
    {
      "ts": 1703847000,
      "ts_str": "Fri, 29 Dec 2023 10:50:00 GMT",
      "price": "8.0000",
      "base": "500.0",
      "quote": "4000.0",
      "tx_hash": "0xabcd...1234",
      "prev_tail": "0x0000...0000",
      "order_root": "0xabcd...1234",
      "filled_pct": 0,
      "seller": "mJUaYn...",
      "type": "order"
    }
  ],
  "count": 10
}
```

---

#### Filter by Order Hash

Find all events related to a specific order (by root or tail hash).

```bash
srv_dex history -net TestNet -view events -order 0x1234...abcd
```

```json
{
  "pair": "KEL/USDT",
  "order_root": "0x1234...abcd",
  "history": [...],
  "count": 5
}
```

**Notes:**
- If tail hash is provided, it is automatically resolved to root via ledger lookup.
- Filtering by `-order` uses `order_root` resolution + trade-by-trade root matching (requires ledger access).
- Works with all formats: `events`, `ohlc`, `volume`

**Order OHLCV Example:**

```bash
srv_dex history -net TestNet -view ohlc -order 0x1234...abcd -bucket 3600
```

```json
{
  "pair": "KEL/USDT",
  "order_root": "0x1234...abcd",
  "market_only": true,
  "ohlc": [
    {
      "ts": 1703844000,
      "ts_str": "Fri, 29 Dec 2023 10:00:00 GMT",
      "open": "8.0000",
      "high": "8.0100",
      "low": "7.9900",
      "close": "8.0050",
      "volume_base": "100.5",
      "volume_quote": "804.0",
      "trades": 3
    }
  ],
  "count": 2,
  "totals": {
    "trades": 5,
    "sum_base": "500.0",
    "sum_quote": "4000.0",
    "spot": "8.0050",
    "vwap": "8.0000"
  }
}
```

---

## Governance (Decree)

### General Syntax

```bash
srv_dex decree \
  -net <network_name> \
  -w <wallet_path> \
  -service_key <cert_name> \
  -fee <validator_fee> \
  -method <method_name> \
  <method_params>
```

**Parameters:**
| Parameter | Required | Description |
|-----------|----------|-------------|
| `-net` | Yes | Network name |
| `-w` | Yes | Wallet file path |
| `-service_key` | Yes | Service certificate name for decree signing |
| `-fee` | Yes | Validator fee in native token |
| `-method` | Yes | Decree method (see below) |

---

### Set Global Fee

```bash
srv_dex decree -net TestNet -w admin.dwallet -service_key dex_admin \
  -fee 0.01 \
  -method fee_set \
  -fee_amount 0.05 \
  -fee_addr Ax7y9q...
```

**Parameters:**
| Parameter | Required | Description |
|-----------|----------|-------------|
| `-fee_amount` | Yes | Service fee amount in native tokens |
| `-fee_addr` | Yes | Address to receive service fees |

**Note:** This sets the global native fee fallback used when pair-specific fee is not configured.

---

### Add Trading Pair

```bash
srv_dex decree -net TestNet -w admin.dwallet -service_key dex_admin \
  -fee 0.01 \
  -method pair_add \
  -token_base KEL \
  -token_quote USDT \
  [-net_base TestNet] \
  [-net_quote TestNet] \
  [-fee_pct 2.0]
```

**Parameters:**
| Parameter | Required | Description |
|-----------|----------|-------------|
| `-token_base` | Yes | Base token ticker |
| `-token_quote` | Yes | Quote token ticker |
| `-net_base` | No | Base token network (default: `-net`) |
| `-net_quote` | No | Quote token network (default: `-net`) |
| `-fee_pct` | No | Percent fee (0.1% step) |
| `-fee_native` | No | Native fee per trade (0.01 step) |
| `-fee_config` | No | Raw config byte (hex) |

**Fee Options (mutually exclusive):**
- `-fee_pct <percent>` — Percent fee from INPUT token (e.g., `2.0` = 2%)
- `-fee_native <amount>` — Fixed native token fee per trade
- `-fee_config <byte>` — Raw config byte (for advanced use)

**Note:** `fee_config` encoding uses mode/value (native vs percent) as described in `02_FEE_SYSTEM.md`.

---

### Remove Trading Pair

```bash
srv_dex decree -net TestNet -w admin.dwallet -service_key dex_admin \
  -fee 0.01 \
  -method pair_remove \
  -token_base KEL \
  -token_quote USDT
```

**Parameters:**
| Parameter | Required | Description |
|-----------|----------|-------------|
| `-token_base` | Yes | Base token ticker |
| `-token_quote` | Yes | Quote token ticker |
| `-net_base` | No | Base token network (default: `-net`) |
| `-net_quote` | No | Quote token network (default: `-net`) |

**Note:** Fee parameters (`-fee_pct`, `-fee_native`, `-fee_config`) are not allowed for `pair_remove`.

---

### Set Pair Fee

```bash
srv_dex decree -net TestNet -w admin.dwallet -service_key dex_admin \
  -fee 0.01 \
  -method pair_fee_set \
  -token_base KEL \
  -token_quote USDT \
  -fee_pct 1.5
```

**Parameters:**
| Parameter | Required | Description |
|-----------|----------|-------------|
| `-token_base` | Yes | Base token ticker |
| `-token_quote` | Yes | Quote token ticker |
| `-net_base` | No | Base token network (default: `-net`) |
| `-net_quote` | No | Quote token network (default: `-net`) |
| `-fee_pct` | One of | Percent fee (0.1% step) |
| `-fee_native` | One of | Native fee per trade (0.01 step) |
| `-fee_config` | One of | Raw config byte (hex) |

**Note:** Exactly one of `-fee_pct`, `-fee_native`, or `-fee_config` is required.

---

### Set All Pairs Fee

```bash
srv_dex decree -net TestNet -w admin.dwallet -service_key dex_admin \
  -fee 0.01 \
  -method pair_fee_set_all \
  -fee_pct 2.0
```

**Parameters:**
| Parameter | Required | Description |
|-----------|----------|-------------|
| `-fee_pct` | One of | Percent fee for all pairs (0.1% step) |
| `-fee_native` | One of | Native fee for all pairs (0.01 step) |
| `-fee_config` | One of | Raw config byte (hex) |

**Note:** Exactly one of `-fee_pct`, `-fee_native`, or `-fee_config` is required. Parameters `-fee_amount` and `-fee_addr` are not allowed for this method.

---

## Migration

### Migrate Legacy Order

```bash
srv_dex migrate \
  -net <network_name> \
  -from <tx_hash> \
  -rate <new_rate> \
  -fee <validator_fee> \
  -w <wallet_path>
```

Converts legacy DEX v1 orders to v2 format.
`-rate` is interpreted as legacy XCHANGE price (BUY per SELL) and converted to canonical QUOTE/BASE when needed.

See also: [DEX migration sync](09_MIGRATION_SYNC.md).

---

## Output Formats

### JSON Output

Most commands support JSON output for programmatic access:

```bash
srv_dex orders -net TestNet -pair KEL/USDT
```

```json
{
  "orders": [
    {
      "side": "ASK",
      "root": "0x123...",
      "tail": "0x456...",
      "price": "2.500000000000000000",
      "value_sell": "100.000000000000000000",
      "filled_pct": 0,
      "seller": "mJUUJk5RwvMCFv6gHJjRdQqLqw3MPHaNS7w9w2w3KtKjoZu4MNH64G",
      "created": "Wed, 25 Dec 2024 12:00:00 GMT",
      "expires": "Fri, 25 Dec 2025 12:00:00 GMT",
      "ts": 1735128000,
      "min_fill_pct": 50,
      "min_fill_from_origin": false
    },
    {
      "side": "BID",
      "root": "0x789...",
      "tail": "0xabc...",
      "price": "2.400000000000000000",
      "value_sell": "50.000000000000000000",
      "filled_pct": 0,
      "seller": "mJUUJkA2B3C4D5E6F7G8H9I0J1K2L3M4N5O6P7Q8R9S0T1U2V3W4",
      "created": "Wed, 25 Dec 2024 11:58:20 GMT",
      "ts": 1735127900,
      "min_fill_pct": 0,
      "min_fill_from_origin": false
    }
  ]
}
```

**Output Fields:**
| Field | Description |
|-------|-------------|
| `side` | Order direction: `ASK` (sell base) or `BID` (buy base) |
| `root` | Root transaction hash (order origin) |
| `tail` | Tail transaction hash (current state) |
| `price` | Exchange rate (quote per base unit) |
| `value_sell` | Remaining sell amount |
| `filled_pct` | Current fill percentage (0-100) relative to last update |
| `seller` | Seller wallet address |
| `created` | Creation timestamp (RFC822 format) |
| `expires` | Expiration timestamp (RFC822), omitted if no expiration |
| `ts` | Numeric timestamp (for programmatic sorting) |
| `min_fill_pct` | Minimum fill percentage (0-100) |
| `min_fill_from_origin` | If true, min_fill is calculated from original order value |

**Note:** When `-pair` is omitted, each order includes an additional `pair` field.

---

## Error Handling

Commands return exit codes:
- `0` — Success
- Non-zero — Error (with descriptive message)

**Example:**
```bash
srv_dex purchase -net TestNet -order 0xINVALID...
# Error: Order not found
# Exit code: 1
```



