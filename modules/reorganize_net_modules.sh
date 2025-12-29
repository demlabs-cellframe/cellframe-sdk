#!/bin/bash

echo "🔧 Реорганизация net-* модулей → net/"

# 1. Создаем структуру директорий
mkdir -p net/core
mkdir -p net/tx
mkdir -p net/srv

# 2. Перемещаем net-core → net/core
if [ -d "net-core" ]; then
    mv net-core/* net/core/ 2>/dev/null
    rmdir net-core
    echo "✅ net-core → net/core"
fi

# 3. Перемещаем net-tx → net/tx
if [ -d "net-tx" ]; then
    mv net-tx/* net/tx/ 2>/dev/null
    rmdir net-tx
    echo "✅ net-tx → net/tx"
fi

# 4. Перемещаем все net-srv-* → net/srv/*
for dir in net-srv-*; do
    if [ -d "$dir" ]; then
        NAME=${dir#net-srv-}
        mkdir -p "net/srv/$NAME"
        mv "$dir"/* "net/srv/$NAME/" 2>/dev/null
        rmdir "$dir"
        echo "✅ $dir → net/srv/$NAME"
    fi
done

# 5. Перемещаем базовый net-srv → net/srv/base
if [ -d "net-srv" ]; then
    mkdir -p net/srv/base
    mv net-srv/* net/srv/base/ 2>/dev/null
    rmdir net-srv
    echo "✅ net-srv → net/srv/base"
fi

echo ""
echo "📂 Новая структура:"
tree -L 3 net/ -d 2>/dev/null || find net/ -type d | head -20

echo ""
echo "🎯 ИТОГО: Все net-* модули внутри net/"
