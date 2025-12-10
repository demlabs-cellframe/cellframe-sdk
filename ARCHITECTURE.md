# Архитектура CellFrame SDK - Иерархия модулей

## Чистая архитектура без циклических зависимостей

### Уровень 1: Базовый (Common)
- **common** - базовые типы и структуры данных
- **ledger** - учет транзакций и балансов
- **chain** - блокчейн структуры

### Уровень 2: Сервисная инфраструктура
- **net-srv** - базовый интерфейс для сервисов
  - Предоставляет абстракции для работы сервисов
  - НЕ зависит от конкретных сервисов
  - НЕ зависит от net модуля
  - Использует callbacks для интеграции с net

### Уровень 3: Сервисы
Все сервисы зависят **ТОЛЬКО** от net-srv:
- **stake** - стейкинг
- **vpn** - VPN сервис
- **xchange** - обмен
- **voting** - голосование
- **bridge** - мосты
- **app**, **datum** - приложения

**Важно**: Сервисы НЕ зависят от net напрямую!

### Уровень 4: Consensus
- **consensus/esbocs** - консенсус
  - Зависит от chain
  - НЕ зависит от net напрямую

### Уровень 5: Network Integration
- **net** - сетевой модуль
  - Интегрирует все: chain, ledger, consensus, services
  - Зависит от net-srv и всех сервисов
  - Регистрирует callbacks в net-srv для доступа к своим функциям
  
### Уровень 6: Mempool & Types
- **mempool** - пул транзакций
  - Зависит от ledger, chain
  - НЕ зависит от wallet, net
- **type/blocks** - блочный тип chain
  - Зависит от chain, mempool

### Уровень 7: High-level
- **compose** - композиция транзакций
- **wallet** - кошельки (самый верхний уровень)
- **node-cli-cmd** - CLI команды

## Ключевые принципы

1. **Dependency Inversion**: net-srv предоставляет интерфейс, net регистрирует реализацию
2. **No Circular Dependencies**: Строгая иерархия без циклов
3. **Service Independence**: Сервисы не знают о net, только о net-srv
4. **Clean Layering**: Каждый уровень зависит только от нижележащих

## Решенные проблемы

### До рефакторинга:
- Циклы: wallet ↔ net ↔ services ↔ mempool
- Сервисы напрямую зависели от net
- Mempool зависел от wallet и net
- Ledger зависел от net

### После рефакторинга:
- ✅ Убраны все циклы
- ✅ Сервисы зависят только от net-srv
- ✅ Mempool независим от wallet/net
- ✅ Ledger независим от net
- ✅ Функции создания TX перенесены из mempool в blocks
- ✅ Compose функции вынесены из mempool в compose модуль

## Интеграция через callbacks и ledger registry

### Ledger Registry
Ledger имеет собственный глобальный реестр:
- `dap_ledger_find_by_name(name)` - поиск по имени
- `dap_ledger_find_by_net_id(net_id)` - поиск по network ID

Сервисы получают ledger напрямую, без зависимости от net!

### Net-srv callbacks (минимальные)
Net-srv предоставляет только функции-обертки для получения IDs:
- `dap_chain_net_srv_get_chain_id_by_name()`
- `dap_chain_net_srv_get_chain_id_by_type()`
- `dap_chain_net_srv_get_net_id_by_name()`

Net регистрирует реализации при инициализации:
```c
dap_chain_net_srv_set_net_callbacks(
    &dap_chain_net_get_chain_id_by_name,
    &dap_chain_net_get_chain_id_by_type,
    &dap_chain_net_get_net_id_by_name
);
```

Это позволяет сервисам работать с сетью через IDs и ledger без прямой зависимости!
