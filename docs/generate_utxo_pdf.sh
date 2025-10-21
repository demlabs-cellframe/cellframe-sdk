#!/usr/bin/env bash
#
# generate_utxo_pdf.sh - Генерация PDF из UTXO_BLOCKING_EXAMPLES.md
#
# Использование:
#   ./generate_utxo_pdf.sh [output_file.pdf]
#
# Требования:
#   - pandoc (для конвертации markdown в PDF)
#   - texlive (LaTeX движок для pandoc)
#   - texlive-xetex (для поддержки Unicode и современных шрифтов)
#
# Установка зависимостей:
#   Debian/Ubuntu:
#     sudo apt-get install pandoc texlive texlive-xetex texlive-fonts-recommended texlive-latex-extra
#   
#   macOS (Homebrew):
#     brew install pandoc
#     brew install --cask mactex
#   
#   Fedora/RHEL:
#     sudo dnf install pandoc texlive texlive-xetex

set -euo pipefail

# Цвета для вывода
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Функции для цветного вывода
log_info() {
    echo -e "${BLUE}[INFO]${NC} $*"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $*"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $*"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $*"
}

# Получаем абсолютный путь к директории скрипта
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
INPUT_FILE="${SCRIPT_DIR}/UTXO_BLOCKING_EXAMPLES.md"
DEFAULT_OUTPUT="${SCRIPT_DIR}/UTXO_BLOCKING_EXAMPLES.pdf"
OUTPUT_FILE="${1:-${DEFAULT_OUTPUT}}"

# Временные файлы
TEMP_HEADER="${SCRIPT_DIR}/.pdf_header.yaml"

# Проверяем наличие входного файла
if [[ ! -f "${INPUT_FILE}" ]]; then
    log_error "Файл ${INPUT_FILE} не найден!"
    exit 1
fi

# Проверяем наличие pandoc
if ! command -v pandoc &> /dev/null; then
    log_error "pandoc не установлен!"
    echo ""
    echo "Установите pandoc:"
    echo "  Debian/Ubuntu:  sudo apt-get install pandoc texlive-xetex"
    echo "  macOS:          brew install pandoc && brew install --cask mactex"
    echo "  Fedora/RHEL:    sudo dnf install pandoc texlive-xetex"
    exit 1
fi

# Функция для создания YAML метаданных
create_metadata() {
    cat > "${TEMP_HEADER}" <<'EOF'
---
title: "UTXO Blocking Mechanism - Usage Examples"
subtitle: "Cellframe SDK Documentation"
author: "Cellframe Development Team"
date: \today
documentclass: article
geometry:
  - top=2cm
  - bottom=2cm
  - left=2cm
  - right=2cm
fontsize: 11pt
numbersections: true
toc: true
toc-depth: 3
colorlinks: true
linkcolor: blue
urlcolor: blue
header-includes: |
  \usepackage{fancyhdr}
  \pagestyle{fancy}
  \fancyhead[L]{UTXO Blocking Mechanism}
  \fancyhead[R]{\thepage}
  \fancyfoot[C]{Cellframe SDK}
  \usepackage{listings}
  \usepackage{xcolor}
  \lstset{
    basicstyle=\ttfamily\small,
    backgroundcolor=\color{gray!10},
    frame=single,
    breaklines=true,
    columns=fullflexible
  }
---
EOF
}

# Функция для очистки временных файлов
cleanup() {
    if [[ -f "${TEMP_HEADER}" ]]; then
        rm -f "${TEMP_HEADER}"
    fi
}

# Регистрируем cleanup при выходе
trap cleanup EXIT

# Основная функция генерации PDF
generate_pdf() {
    log_info "Генерация PDF из ${INPUT_FILE}..."
    log_info "Выходной файл: ${OUTPUT_FILE}"
    
    # Создаём метаданные
    create_metadata
    
    # Объединяем метаданные и исходный файл
    log_info "Обработка markdown..."
    local temp_input="${SCRIPT_DIR}/.temp_input.md"
    cat "${TEMP_HEADER}" "${INPUT_FILE}" > "${temp_input}"
    
    # Генерируем PDF с помощью pandoc
    log_info "Генерация PDF с помощью pandoc..."
    
    # Проверяем наличие XeLaTeX для лучшей поддержки Unicode
    if command -v xelatex &> /dev/null; then
        PDF_ENGINE="xelatex"
        log_info "Используется XeLaTeX для генерации PDF"
    else
        PDF_ENGINE="pdflatex"
        log_warning "XeLaTeX не найден, используется pdflatex (ограниченная поддержка Unicode)"
    fi
    
    # Запускаем pandoc
    if pandoc "${temp_input}" \
        --pdf-engine="${PDF_ENGINE}" \
        --variable urlcolor=blue \
        --variable linkcolor=blue \
        --variable toccolor=blue \
        --highlight-style=tango \
        --listings \
        -o "${OUTPUT_FILE}" 2>&1 | grep -v "Warning"; then
        
        log_success "PDF успешно создан: ${OUTPUT_FILE}"
        
        # Показываем размер файла
        local file_size
        if command -v du &> /dev/null; then
            file_size=$(du -h "${OUTPUT_FILE}" | cut -f1)
            log_info "Размер файла: ${file_size}"
        fi
        
        # Показываем количество страниц (если есть pdfinfo)
        if command -v pdfinfo &> /dev/null; then
            local page_count
            page_count=$(pdfinfo "${OUTPUT_FILE}" 2>/dev/null | grep "Pages:" | awk '{print $2}')
            if [[ -n "${page_count}" ]]; then
                log_info "Количество страниц: ${page_count}"
            fi
        fi
        
        rm -f "${temp_input}"
        return 0
    else
        log_error "Ошибка при генерации PDF!"
        rm -f "${temp_input}"
        return 1
    fi
}

# Функция проверки зависимостей
check_dependencies() {
    local missing_deps=()
    
    # Проверяем pandoc
    if ! command -v pandoc &> /dev/null; then
        missing_deps+=("pandoc")
    fi
    
    # Проверяем LaTeX
    if ! command -v pdflatex &> /dev/null && ! command -v xelatex &> /dev/null; then
        missing_deps+=("texlive (pdflatex or xelatex)")
    fi
    
    if [[ ${#missing_deps[@]} -gt 0 ]]; then
        log_error "Отсутствуют зависимости: ${missing_deps[*]}"
        echo ""
        echo "Установите недостающие пакеты:"
        echo ""
        echo "Debian/Ubuntu:"
        echo "  sudo apt-get install pandoc texlive texlive-xetex texlive-fonts-recommended texlive-latex-extra"
        echo ""
        echo "macOS (Homebrew):"
        echo "  brew install pandoc"
        echo "  brew install --cask mactex"
        echo ""
        echo "Fedora/RHEL:"
        echo "  sudo dnf install pandoc texlive texlive-xetex"
        return 1
    fi
    
    return 0
}

# Главная функция
main() {
    echo "╔════════════════════════════════════════════════════════════╗"
    echo "║   UTXO Blocking Documentation PDF Generator                ║"
    echo "║   Cellframe SDK                                            ║"
    echo "╚════════════════════════════════════════════════════════════╝"
    echo ""
    
    # Проверяем зависимости
    if ! check_dependencies; then
        exit 1
    fi
    
    # Генерируем PDF
    if generate_pdf; then
        echo ""
        log_success "✅ Генерация завершена успешно!"
        echo ""
        echo "Для просмотра PDF:"
        echo "  xdg-open ${OUTPUT_FILE}    # Linux"
        echo "  open ${OUTPUT_FILE}        # macOS"
        exit 0
    else
        echo ""
        log_error "❌ Генерация завершена с ошибками!"
        exit 1
    fi
}

# Запускаем главную функцию
main "$@"

