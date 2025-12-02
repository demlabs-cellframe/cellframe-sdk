# DEX CLI Commands Reference

## Order Management

### `srv_dex order create`
Create new limit order on DEX. Locks specified amount of sell token in conditional output (OUT_COND). Order becomes visible in orderbook and available for purchase by other users.

| Parameter | Required | Description |
|-----------|----------|-------------|
| `-net` | yes | Network name |
| `-token_sell` | yes | Sell token ticker |
| `-token_buy` | yes | Buy token ticker |
| `-w` | yes | Owner wallet (must have sufficient balance) |
| `-value` | yes | Amount of sell token to lock |
| `-rate` | yes | Price in canonical form QUOTE/BASE |
| `-fee` | yes | Validator fee in native token |

**Example:**
```
srv_dex order create -net Backbone -token_sell KEL -token_buy USDT -w alice -value 100.0 -rate 2.5 -fee 0.1
```

Creates ASK order: sell 100 KEL at price 2.5 USDT per KEL.

---

### `srv_dex order update`
Modify value of existing order without changing its root hash (order identity preserved). Owner can increase or decrease locked amount. Rate and other parameters are immutable.

| Parameter | Required | Description |
|-----------|----------|-------------|
| `-net` | yes | Network name |
| `-order` | yes | Order root TX hash |
| `-w` | yes | Owner wallet |
| `-value_new` | no | New locked value |
| `-fee` | yes | Validator fee |

**Notes:**
- Increase: additional tokens collected from wallet
- Decrease: surplus tokens refunded to wallet
- Rate cannot be changed (immutable)

**Example:**
```
srv_dex order update -net Backbone -order 0xABC123... -w alice -value_new 150.0 -fee 0.1
```

---

### `srv_dex order remove`
Cancel order and refund all locked tokens to owner. Order becomes inactive and removed from orderbook. Works for both untouched orders and partially filled (leftover) orders.

| Parameter | Required | Description |
|-----------|----------|-------------|
| `-net` | yes | Network name |
| `-order` | yes | Order hash (root or current tail) |
| `-w` | yes | Owner wallet |
| `-fee` | yes | Validator fee |

**Example:**
```
srv_dex order remove -net Backbone -order 0xABC123... -w alice -fee 0.1
```

---

## Purchase Commands

### `srv_dex purchase`
Execute trade against single order. Supports full and partial fills. Buyer pays in buy_token, receives sell_token. Creates seller payout and optional buyer leftover order.

| Parameter | Required | Description |
|-----------|----------|-------------|
| `-net` | yes | Network name |
| `-order` | yes | Target order hash |
| `-w` | yes | Buyer wallet |
| `-value` | yes | Trade amount |
| `-unit` | no | Value units: `sell` (default) or `buy` |
| `-fee` | yes | Validator fee |
| `-create_leftover_order` | no | Create order from unspent budget |
| `-leftover_rate` | no | Rate for leftover order |

**Example:**
```
srv_dex purchase -net Backbone -order 0xABC123... -w bob -value 50.0 -unit sell -fee 0.1
```

Buys 50 units of sell_token from the order.

---

### `srv_dex purchase_multi`
Execute trade against multiple orders in single transaction. Orders are filled in specified sequence until budget exhausted. Atomic: either all succeed or transaction rejected.

| Parameter | Required | Description |
|-----------|----------|-------------|
| `-net` | yes | Network name |
| `-orders` | yes | Comma-separated order hashes |
| `-w` | yes | Buyer wallet |
| `-value` | yes | Total trade budget |
| `-unit` | no | Value units: `sell` or `buy` |
| `-fee` | yes | Validator fee |
| `-create_leftover_order` | no | Create order from unspent budget |
| `-leftover_rate` | no | Rate for leftover order |

**Example:**
```
srv_dex purchase_multi -net Backbone -orders 0xAAA...,0xBBB...,0xCCC... -w bob -value 100.0 -fee 0.1
```

---

### `srv_dex purchase_auto`
Automatic order matching: finds best-priced orders for given pair and executes trade. Orders sorted by price (best first). Supports rate limit and dry-run simulation.

| Parameter | Required | Description |
|-----------|----------|-------------|
| `-net` | yes | Network name |
| `-token_sell` | yes | Token buyer sells (pays with) |
| `-token_buy` | yes | Token buyer wants to receive |
| `-w` | yes | Buyer wallet |
| `-value` | yes | Trade amount |
| `-unit` | no | Value units: `sell` or `buy` |
| `-min_rate` | no | Minimum acceptable rate (reject worse) |
| `-fee` | no | Validator fee |
| `-create_leftover_order` | no | Create order from unspent budget |
| `-leftover_rate` | no | Rate for leftover order |
| `-dry-run` | no | Simulate only, don't execute |

**Example:**
```
srv_dex purchase_auto -net Backbone -token_sell USDT -token_buy KEL -w bob -value 100.0 -min_rate 0.4 -fee 0.1
```

Automatically buys KEL with 100 USDT at best available prices, rejecting orders worse than 0.4 KEL/USDT.

---

## Query Commands

### `srv_dex orders`
List all active orders for specified pair. Returns order details: hash, value, rate, seller address, timestamps. Supports filtering by seller.

| Parameter | Required | Description |
|-----------|----------|-------------|
| `-net` | yes | Network name |
| `-pair` | yes | Trading pair `BASE/QUOTE` |
| `-seller` | no | Filter by seller address |
| `-limit` | no | Max results |
| `-offset` | no | Pagination offset |

**Example:**
```
srv_dex orders -net Backbone -pair KEL/USDT
srv_dex orders -net Backbone -pair KEL/USDT -seller hBkmWQ...
```

---

### `srv_dex orderbook`
Aggregated order book with price levels. Groups orders by price, sums volumes. Useful for market depth visualization. Supports price tick binning and cumulative volumes.

| Parameter | Required | Description |
|-----------|----------|-------------|
| `-net` | yes | Network name |
| `-pair` | yes | Trading pair `BASE/QUOTE` |
| `-depth` | no | Number of levels per side (default 20) |
| `-tick_price` | no | Price step for level aggregation |
| `-tick` | no | Tick decimals (alternative to tick_price) |
| `cumulative` | no | Add cumulative volume columns |

**Output:** Arrays of asks and bids with price, volume_base, volume_quote, order_count.

**Example:**
```
srv_dex orderbook -net Backbone -pair KEL/USDT -depth 10 cumulative
```

---

### `srv_dex history`
Transaction history for specific order. Shows all state changes: creation, partial fills, updates, cancellation. Traces order chain from root to current tail.

| Parameter | Required | Description |
|-----------|----------|-------------|
| `-net` | yes | Network name |
| `-order` | yes | Order root hash |

**Output:** Array of transactions with type, value changes, timestamps.

---

### `srv_dex status`
Aggregated statistics for trading pair: order count, total volume, average rate. Separate stats for asks and bids.

| Parameter | Required | Description |
|-----------|----------|-------------|
| `-net` | yes | Network name |
| `-pair` | yes | Trading pair `BASE/QUOTE` |
| `-seller` | no | Filter by seller address |

---

## Analytics Commands

### `srv_dex market_rate`
Calculate volume-weighted average price (VWAP) for period. Analyzes executed trades to determine effective market rate. Supports time bucketing for rate history.

| Parameter | Required | Description |
|-----------|----------|-------------|
| `-net` | yes | Network name |
| `-pair` | yes | Trading pair |
| `-from` | no | Period start (Unix timestamp) |
| `-to` | no | Period end (Unix timestamp) |
| `-bucket` | no | Bucket size in seconds (for time series) |

**Example:**
```
srv_dex market_rate -net Backbone -pair KEL/USDT -from 1700000000 -to 1700100000 -bucket 3600
```

Returns hourly VWAP for specified period.

---

### `srv_dex tvl`
Total Value Locked: sum of all token amounts currently locked in active orders across all pairs.

| Parameter | Required | Description |
|-----------|----------|-------------|
| `-net` | yes | Network name |
| `-token` | yes | Token ticker |

**Example:**
```
srv_dex tvl -net Backbone -token KEL
```

---

### `srv_dex spread`
Current bid-ask spread: difference between best ask and best bid prices. Indicates market liquidity and trading costs.

| Parameter | Required | Description |
|-----------|----------|-------------|
| `-net` | yes | Network name |
| `-pair` | yes | Trading pair |

**Output:** best_ask, best_bid, spread_abs, spread_pct

---

### `srv_dex volume`
Trading volume for period: sum of executed trade values. Supports time bucketing for volume history charts.

| Parameter | Required | Description |
|-----------|----------|-------------|
| `-net` | yes | Network name |
| `-pair` | yes | Trading pair |
| `-from` | no | Period start |
| `-to` | no | Period end |
| `-bucket` | no | Bucket size in seconds |

---

### `srv_dex slippage`
Estimate price slippage for hypothetical trade of given size. Simulates market order execution against current orderbook.

| Parameter | Required | Description |
|-----------|----------|-------------|
| `-net` | yes | Network name |
| `-pair` | yes | Trading pair |
| `-value` | yes | Trade size |
| `-side` | no | `buy` or `sell` (default: buy) |

**Output:** average_price, slippage_pct, orders_consumed

---

## Administration Commands

### `srv_dex pairs`
List all whitelisted trading pairs. Only whitelisted pairs can have active orders.

| Parameter | Required | Description |
|-----------|----------|-------------|
| `-net` | yes | Network name |

**Output:** Array of pairs with base/quote tokens, fee_config.

---

### `srv_dex cancel_all_by_seller`
Mass cancel all orders by specific seller. Useful for emergency exit or account migration. Supports limit and dry-run.

| Parameter | Required | Description |
|-----------|----------|-------------|
| `-net` | yes | Network name |
| `-seller` | yes | Seller address |
| `-w` | yes | Signing wallet (must be seller) |
| `-fee` | yes | Validator fee per cancellation |
| `-limit` | no | Max orders to cancel |
| `-dry-run` | no | List orders without cancelling |

---

### `srv_dex migrate`
Migrate order from legacy XCHANGE service to DEX. Consumes XCHANGE conditional output, creates new DEX order with specified rate.

| Parameter | Required | Description |
|-----------|----------|-------------|
| `-net` | yes | Network name |
| `-from` | yes | XCHANGE TX hash `tx_hash[:out_idx]` |
| `-rate` | yes | New rate for DEX order |
| `-w` | yes | Owner wallet |
| `-fee` | yes | Validator fee |

---

### `srv_dex decree`
Governance operations via signed decrees. Requires appropriate signing authority.

| Parameter | Required | Description |
|-----------|----------|-------------|
| `-net` | yes | Network name |
| `-w` | yes | Authority wallet |
| `-method` | yes | Operation type (see below) |

**Methods:**

#### `fee_set`
Set global network fee for DEX transactions.
```
srv_dex decree -net Backbone -w authority -method fee_set -fee_amount 1.0 -fee_addr hXYZ...
```

#### `pair_add`
Whitelist new trading pair.
```
srv_dex decree -net Backbone -w authority -method pair_add -token_base KEL -token_quote USDT -fee_config 0x82
```

#### `pair_remove`
Remove pair from whitelist (existing orders remain until cancelled).
```
srv_dex decree -net Backbone -w authority -method pair_remove -token_base KEL -token_quote USDT
```

#### `pair_fee_set`
Set service fee for specific pair.
```
srv_dex decree -net Backbone -w authority -method pair_fee_set -token_base KEL -token_quote USDT -fee_config 0x82
```

#### `pair_fee_set_all`
Set service fee for all pairs.
```
srv_dex decree -net Backbone -w authority -method pair_fee_set_all -fee_config 0x82
```

**fee_config byte format:**
- Bits 0-6: Fee percentage (0-100)
- Bit 7: Fee source (0 = buyer pays from QUOTE, 1 = seller pays from BASE)

Example: `0x82` = 2% fee paid by seller from BASE token.
