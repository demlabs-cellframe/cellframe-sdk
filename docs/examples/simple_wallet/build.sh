#!/bin/bash

# Скрипт сборки CellFrame SDK Simple Wallet примера с использованием CMake

set -e

echo "=== CellFrame SDK Simple Wallet Example Build Script ==="
echo

# Создание директории сборки
echo "📁 Creating build directory..."
mkdir -p build
cd build

# Конфигурация с CMake
echo "⚙️  Configuring with CMake..."
cmake .. -DCMAKE_BUILD_TYPE=Release

echo
echo "🔨 Building..."
make -j$(nproc)

echo
echo "✅ Build completed successfully!"
echo
echo "📍 Executable location: $(pwd)/simple_wallet"
echo
echo "🚀 To run the example:"
echo "   cd build && ./simple_wallet"
echo
echo "📦 To install system-wide:"
echo "   sudo make install"
echo
echo "🧹 To clean build files:"
echo "   rm -rf build/"


