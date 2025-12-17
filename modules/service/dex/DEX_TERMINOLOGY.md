# Терминология DEX

## Торговая пара: CELL/USDT

- **BASE** = CELL (актив, который торгуется)
- **QUOTE** = USDT (актив для оценки стоимости)
- **Rate** = цена 1 BASE в единицах QUOTE (rate=0.5 означает 1 CELL = 0.5 USDT)

## ASK — продажа BASE

| | |
|-|-|
| Действие | Продаю CELL |
| sell_token | CELL (BASE) |
| buy_token | USDT (QUOTE) |
| amount | Количество CELL (заблокировано в out_cond) |
| Rate | Сколько USDT хочу за 1 CELL |

Пример: ASK 100 CELL по rate 0.5 = продаю 100 CELL, получаю 50 USDT

## BID — покупка BASE

| | |
|-|-|
| Действие | Покупаю CELL |
| sell_token | USDT (QUOTE) |
| buy_token | CELL (BASE) |
| amount | Количество USDT (заблокировано в out_cond) |
| Rate | Сколько USDT плачу за 1 CELL |

Пример: BID 50 USDT по rate 0.5 = плачу 50 USDT, получаю 100 CELL

## Общее правило

`out_cond.value` = количество `sell_token` (всегда то, что заблокировано продавцом)

## Стакан ордеров

- **Best ASK** = минимальная цена продажи (самое дешёвое предложение)
- **Best BID** = максимальная цена покупки (лучшее предложение купить)
- **Spread** = Best ASK - Best BID

## В коде

```c
DEX_SIDE_ASK (0): продавец отдаёт BASE, получает QUOTE
DEX_SIDE_BID (1): продавец отдаёт QUOTE, получает BASE
```
