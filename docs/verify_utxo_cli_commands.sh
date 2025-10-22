#!/usr/bin/env bash
#
# verify_utxo_cli_commands.sh - Проверка соответствия CLI команд в документации реальной реализации
#
# Проверяет:
#   1. Все ли команды из UTXO_BLOCKING_EXAMPLES.md реализованы в CLI
#   2. Соответствие параметров команд
#   3. Покрытие тестами
#
# Использование:
#   ./verify_utxo_cli_commands.sh

set -uo pipefail

# Цвета для вывода
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
MAGENTA='\033[0;35m'
NC='\033[0m' # No Color

# Получаем абсолютный путь к корню проекта cellframe-sdk
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SDK_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

# Файлы для проверки
DOC_FILE="${SCRIPT_DIR}/UTXO_BLOCKING_EXAMPLES.md"
CLI_IMPL="${SDK_ROOT}/modules/net/dap_chain_node_cli_cmd.c"
CLI_HELP="${SDK_ROOT}/modules/net/dap_chain_node_cli.c"
COVERAGE_ANALYSIS="${SDK_ROOT}/UTXO_CLI_COVERAGE_ANALYSIS.md"
INTEGRATION_TEST="${SDK_ROOT}/tests/integration/utxo_blocking_integration_test.c"
CLI_TEST="${SDK_ROOT}/tests/integration/utxo_blocking_cli_integration_test.c"

# Счётчики
TOTAL_CHECKS=0
PASSED_CHECKS=0
FAILED_CHECKS=0
WARNING_CHECKS=0

# Функции для цветного вывода
log_info() {
    echo -e "${BLUE}[INFO]${NC} $*"
}

log_success() {
    echo -e "${GREEN}[✓ PASS]${NC} $*"
    ((PASSED_CHECKS++))
    ((TOTAL_CHECKS++))
}

log_warning() {
    echo -e "${YELLOW}[⚠ WARN]${NC} $*"
    ((WARNING_CHECKS++))
    ((TOTAL_CHECKS++))
}

log_error() {
    echo -e "${RED}[✗ FAIL]${NC} $*"
    ((FAILED_CHECKS++))
    ((TOTAL_CHECKS++))
}

section_header() {
    echo ""
    echo -e "${CYAN}═══════════════════════════════════════════════════════════${NC}"
    echo -e "${CYAN}  $*${NC}"
    echo -e "${CYAN}═══════════════════════════════════════════════════════════${NC}"
}

subsection_header() {
    echo ""
    echo -e "${MAGENTA}─── $* ───${NC}"
}

# Проверка наличия файлов
check_files_exist() {
    section_header "1. Проверка наличия файлов"
    
    if [[ -f "${DOC_FILE}" ]]; then
        log_success "Документация найдена: ${DOC_FILE}"
    else
        log_error "Документация не найдена: ${DOC_FILE}"
        return 1
    fi
    
    if [[ -f "${CLI_IMPL}" ]]; then
        log_success "CLI реализация найдена: ${CLI_IMPL}"
    else
        log_error "CLI реализация не найдена: ${CLI_IMPL}"
    fi
    
    if [[ -f "${CLI_HELP}" ]]; then
        log_success "CLI help найден: ${CLI_HELP}"
    else
        log_error "CLI help не найден: ${CLI_HELP}"
    fi
    
    if [[ -f "${INTEGRATION_TEST}" ]]; then
        log_success "Integration test найден: ${INTEGRATION_TEST}"
    else
        log_warning "Integration test не найден: ${INTEGRATION_TEST}"
    fi
    
    if [[ -f "${CLI_TEST}" ]]; then
        log_success "CLI integration test найден: ${CLI_TEST}"
    else
        log_warning "CLI integration test не найден: ${CLI_TEST}"
    fi
}

# Проверка CLI параметров
check_cli_parameters() {
    section_header "2. Проверка CLI параметров"
    
    subsection_header "2.1. Параметр -utxo_blocked_add"
    
    # Проверяем в документации
    if grep -q "\-utxo_blocked_add" "${DOC_FILE}"; then
        log_success "Документация содержит -utxo_blocked_add"
    else
        log_error "Документация НЕ содержит -utxo_blocked_add"
    fi
    
    # Проверяем в CLI help
    if grep -q "\-utxo_blocked_add" "${CLI_HELP}"; then
        log_success "CLI help содержит -utxo_blocked_add"
    else
        log_error "CLI help НЕ содержит -utxo_blocked_add"
    fi
    
    # Проверяем реализацию в CLI
    if grep -q "utxo_blocked_add" "${CLI_IMPL}"; then
        log_success "CLI реализация обрабатывает -utxo_blocked_add"
    else
        log_error "CLI реализация НЕ обрабатывает -utxo_blocked_add"
    fi
    
    subsection_header "2.2. Параметр -utxo_blocked_remove"
    
    if grep -q "\-utxo_blocked_remove" "${DOC_FILE}"; then
        log_success "Документация содержит -utxo_blocked_remove"
    else
        log_error "Документация НЕ содержит -utxo_blocked_remove"
    fi
    
    if grep -q "\-utxo_blocked_remove" "${CLI_HELP}"; then
        log_success "CLI help содержит -utxo_blocked_remove"
    else
        log_error "CLI help НЕ содержит -utxo_blocked_remove"
    fi
    
    if grep -q "utxo_blocked_remove" "${CLI_IMPL}"; then
        log_success "CLI реализация обрабатывает -utxo_blocked_remove"
    else
        log_error "CLI реализация НЕ обрабатывает -utxo_blocked_remove"
    fi
    
    subsection_header "2.3. Параметр -utxo_blocked_clear"
    
    if grep -q "\-utxo_blocked_clear" "${DOC_FILE}"; then
        log_success "Документация содержит -utxo_blocked_clear"
    else
        log_error "Документация НЕ содержит -utxo_blocked_clear"
    fi
    
    if grep -q "\-utxo_blocked_clear" "${CLI_HELP}"; then
        log_success "CLI help содержит -utxo_blocked_clear"
    else
        log_error "CLI help НЕ содержит -utxo_blocked_clear"
    fi
    
    if grep -q "utxo_blocked_clear" "${CLI_IMPL}"; then
        log_success "CLI реализация обрабатывает -utxo_blocked_clear"
    else
        log_error "CLI реализация НЕ обрабатывает -utxo_blocked_clear"
    fi
}

# Проверка формата UTXO
check_utxo_format() {
    section_header "3. Проверка формата UTXO"
    
    subsection_header "3.1. Формат <tx_hash>:<out_idx>"
    
    # Проверяем документацию
    if grep -q "tx_hash>:<out_idx>" "${DOC_FILE}"; then
        log_success "Документация описывает формат <tx_hash>:<out_idx>"
    else
        log_error "Документация НЕ описывает формат <tx_hash>:<out_idx>"
    fi
    
    # Проверяем что в реализации есть парсинг через ':'
    if grep -q "strchr.*':'" "${CLI_IMPL}" || grep -q "strtok.*\":\\\*\"" "${CLI_IMPL}"; then
        log_success "CLI реализация парсит формат через ':'"
    else
        log_warning "CLI реализация: парсинг через ':' не очевиден в коде"
    fi
    
    subsection_header "3.2. Формат с timestamp: <tx_hash>:<out_idx>:<timestamp>"
    
    if grep -q "tx_hash>:<out_idx>:<timestamp>" "${DOC_FILE}"; then
        log_success "Документация описывает формат с timestamp"
    else
        log_error "Документация НЕ описывает формат с timestamp"
    fi
    
    # Проверяем что реализация поддерживает опциональный timestamp
    if grep -A 10 "utxo_blocked_add\|utxo_blocked_remove" "${CLI_IMPL}" | grep -q "timestamp\|time"; then
        log_success "CLI реализация поддерживает timestamp"
    else
        log_warning "CLI реализация: поддержка timestamp не очевидна"
    fi
}

# Проверка флагов
check_flags() {
    section_header "4. Проверка флагов токенов"
    
    subsection_header "4.1. Флаг UTXO_BLOCKING_DISABLED"
    
    if grep -q "UTXO_BLOCKING_DISABLED" "${DOC_FILE}"; then
        log_success "Документация описывает UTXO_BLOCKING_DISABLED"
    else
        log_error "Документация НЕ описывает UTXO_BLOCKING_DISABLED"
    fi
    
    # Проверяем в header файле
    local token_header="${SDK_ROOT}/modules/common/include/dap_chain_datum_token.h"
    if [[ -f "${token_header}" ]] && grep -q "UTXO_BLOCKING_DISABLED" "${token_header}"; then
        log_success "dap_chain_datum_token.h определяет UTXO_BLOCKING_DISABLED"
    else
        log_warning "UTXO_BLOCKING_DISABLED не найден в заголовочном файле"
    fi
    
    subsection_header "4.2. Флаг UTXO_STATIC_BLOCKLIST"
    
    if grep -q "UTXO_STATIC_BLOCKLIST" "${DOC_FILE}"; then
        log_success "Документация описывает UTXO_STATIC_BLOCKLIST"
    else
        log_error "Документация НЕ описывает UTXO_STATIC_BLOCKLIST"
    fi
    
    if [[ -f "${token_header}" ]] && grep -q "UTXO_STATIC_BLOCKLIST" "${token_header}"; then
        log_success "dap_chain_datum_token.h определяет UTXO_STATIC_BLOCKLIST"
    else
        log_warning "UTXO_STATIC_BLOCKLIST не найден в заголовочном файле"
    fi
}

# Проверка TSD типов
check_tsd_types() {
    section_header "5. Проверка TSD типов"
    
    local token_header="${SDK_ROOT}/modules/common/include/dap_chain_datum_token.h"
    
    subsection_header "5.1. TSD тип для ADD операции"
    
    if [[ -f "${token_header}" ]]; then
        if grep -q "DAP_CHAIN_DATUM_TOKEN_TSD_TYPE_UTXO_BLOCKED_ADD" "${token_header}"; then
            log_success "TSD тип UTXO_BLOCKED_ADD определён"
            
            # Проверяем что используется в реализации
            if grep -q "DAP_CHAIN_DATUM_TOKEN_TSD_TYPE_UTXO_BLOCKED_ADD" "${CLI_IMPL}"; then
                log_success "CLI реализация использует TSD тип UTXO_BLOCKED_ADD"
            else
                log_error "CLI реализация НЕ использует TSD тип UTXO_BLOCKED_ADD"
            fi
        else
            log_error "TSD тип UTXO_BLOCKED_ADD не определён"
        fi
    fi
    
    subsection_header "5.2. TSD тип для REMOVE операции"
    
    if [[ -f "${token_header}" ]]; then
        if grep -q "DAP_CHAIN_DATUM_TOKEN_TSD_TYPE_UTXO_BLOCKED_REMOVE" "${token_header}"; then
            log_success "TSD тип UTXO_BLOCKED_REMOVE определён"
            
            if grep -q "DAP_CHAIN_DATUM_TOKEN_TSD_TYPE_UTXO_BLOCKED_REMOVE" "${CLI_IMPL}"; then
                log_success "CLI реализация использует TSD тип UTXO_BLOCKED_REMOVE"
            else
                log_error "CLI реализация НЕ использует TSD тип UTXO_BLOCKED_REMOVE"
            fi
        else
            log_error "TSD тип UTXO_BLOCKED_REMOVE не определён"
        fi
    fi
    
    subsection_header "5.3. TSD тип для CLEAR операции"
    
    if [[ -f "${token_header}" ]]; then
        if grep -q "DAP_CHAIN_DATUM_TOKEN_TSD_TYPE_UTXO_BLOCKED_CLEAR" "${token_header}"; then
            log_success "TSD тип UTXO_BLOCKED_CLEAR определён"
            
            if grep -q "DAP_CHAIN_DATUM_TOKEN_TSD_TYPE_UTXO_BLOCKED_CLEAR" "${CLI_IMPL}"; then
                log_success "CLI реализация использует TSD тип UTXO_BLOCKED_CLEAR"
            else
                log_error "CLI реализация НЕ использует TSD тип UTXO_BLOCKED_CLEAR"
            fi
        else
            log_error "TSD тип UTXO_BLOCKED_CLEAR не определён"
        fi
    fi
}

# Проверка тестового покрытия
check_test_coverage() {
    section_header "6. Проверка тестового покрытия"
    
    subsection_header "6.1. Unit тесты"
    
    local unit_test="${SDK_ROOT}/tests/unit/utxo_blocking_unit_test.c"
    if [[ -f "${unit_test}" ]]; then
        log_success "Unit тест существует: utxo_blocking_unit_test.c"
    else
        log_warning "Unit тест не найден: utxo_blocking_unit_test.c"
    fi
    
    subsection_header "6.2. Integration тесты (Ledger)"
    
    if [[ -f "${INTEGRATION_TEST}" ]]; then
        log_success "Integration тест существует: utxo_blocking_integration_test.c"
        
        # Проверяем покрытие основных операций
        if grep -q "test_token_update_utxo_blocked_add\|s_test_utxo_blocked_add" "${INTEGRATION_TEST}"; then
            log_success "Есть тест для utxo_blocked_add"
        else
            log_warning "Нет теста для utxo_blocked_add"
        fi
        
        if grep -q "test_token_update_utxo_blocked_remove\|s_test_utxo_blocked_remove" "${INTEGRATION_TEST}"; then
            log_success "Есть тест для utxo_blocked_remove"
        else
            log_warning "Нет теста для utxo_blocked_remove"
        fi
        
        if grep -q "test_token_update_utxo_blocked_clear\|s_test_utxo_blocked_clear" "${INTEGRATION_TEST}"; then
            log_success "Есть тест для utxo_blocked_clear"
        else
            log_warning "Нет теста для utxo_blocked_clear"
        fi
    else
        log_error "Integration тест не найден"
    fi
    
    subsection_header "6.3. CLI Integration тесты"
    
    if [[ -f "${CLI_TEST}" ]]; then
        log_success "CLI integration тест существует: utxo_blocking_cli_integration_test.c"
        
        # Проверяем что тесты вызывают реальные CLI команды
        if grep -q "com_token_update\|dap_cli_cmd_exec" "${CLI_TEST}"; then
            log_success "CLI тесты вызывают реальные CLI функции"
        else
            log_warning "CLI тесты не вызывают CLI функции напрямую"
        fi
    else
        log_warning "CLI integration тест не найден"
    fi
    
    subsection_header "6.4. Анализ покрытия"
    
    if [[ -f "${COVERAGE_ANALYSIS}" ]]; then
        log_success "Анализ покрытия существует: UTXO_CLI_COVERAGE_ANALYSIS.md"
        
        # Проверяем процент покрытия
        if grep -q "52%" "${COVERAGE_ANALYSIS}"; then
            log_warning "Покрытие тестами: 52% (недостаточно)"
        else
            log_info "Проверьте актуальность процента покрытия в ${COVERAGE_ANALYSIS}"
        fi
    else
        log_warning "Анализ покрытия не найден"
    fi
}

# Проверка примеров использования
check_use_cases() {
    section_header "7. Проверка примеров использования"
    
    subsection_header "7.1. Vesting / Lock-up"
    
    if grep -q -i "vesting\|lock-up\|lock up" "${DOC_FILE}"; then
        log_success "Документация содержит примеры vesting/lock-up"
    else
        log_warning "Документация не содержит примеры vesting"
    fi
    
    subsection_header "7.2. Escrow"
    
    if grep -q -i "escrow" "${DOC_FILE}"; then
        log_success "Документация содержит примеры escrow"
    else
        log_warning "Документация не содержит примеры escrow"
    fi
    
    subsection_header "7.3. Security Incident Response"
    
    if grep -q -i "security incident\|suspicious" "${DOC_FILE}"; then
        log_success "Документация содержит примеры реагирования на инциденты"
    else
        log_warning "Документация не содержит примеры реагирования на инциденты"
    fi
}

# Проверка обработки ошибок
check_error_handling() {
    section_header "8. Проверка обработки ошибок"
    
    subsection_header "8.1. Валидация формата UTXO"
    
    # Проверяем что в реализации есть проверка формата
    if grep -q "Invalid UTXO format\|invalid.*format" "${CLI_IMPL}"; then
        log_success "CLI реализация проверяет формат UTXO"
    else
        log_warning "CLI реализация: проверка формата не очевидна"
    fi
    
    # Проверяем что есть тест для невалидного формата
    if [[ -f "${INTEGRATION_TEST}" ]] && grep -q "invalid.*format\|test_invalid_utxo" "${INTEGRATION_TEST}"; then
        log_success "Есть тест для невалидного формата UTXO"
    else
        log_warning "Нет теста для невалидного формата UTXO"
    fi
    
    subsection_header "8.2. Проверка UTXO_STATIC_BLOCKLIST"
    
    if grep -q "UTXO_STATIC_BLOCKLIST" "${DOC_FILE}"; then
        log_success "Документация описывает ошибку UTXO_STATIC_BLOCKLIST"
    else
        log_warning "Документация не описывает ошибку UTXO_STATIC_BLOCKLIST"
    fi
    
    # Проверяем тест для immutability
    if [[ -f "${INTEGRATION_TEST}" ]] && grep -q "static.*blocklist\|immutable" "${INTEGRATION_TEST}"; then
        log_success "Есть тест для UTXO_STATIC_BLOCKLIST enforcement"
    else
        log_warning "Нет теста для UTXO_STATIC_BLOCKLIST enforcement"
    fi
}

# Финальный отчёт
print_summary() {
    section_header "ИТОГОВЫЙ ОТЧЁТ"
    
    echo ""
    echo "Всего проверок: ${TOTAL_CHECKS}"
    echo -e "${GREEN}Успешно:       ${PASSED_CHECKS}${NC}"
    echo -e "${YELLOW}Предупреждения: ${WARNING_CHECKS}${NC}"
    echo -e "${RED}Ошибки:         ${FAILED_CHECKS}${NC}"
    echo ""
    
    local success_rate=0
    if [[ ${TOTAL_CHECKS} -gt 0 ]]; then
        success_rate=$((PASSED_CHECKS * 100 / TOTAL_CHECKS))
    fi
    
    echo -e "Процент успешных проверок: ${success_rate}%"
    echo ""
    
    if [[ ${FAILED_CHECKS} -eq 0 ]] && [[ ${WARNING_CHECKS} -eq 0 ]]; then
        echo -e "${GREEN}✅ ВСЕ ПРОВЕРКИ ПРОЙДЕНЫ УСПЕШНО!${NC}"
        return 0
    elif [[ ${FAILED_CHECKS} -eq 0 ]]; then
        echo -e "${YELLOW}⚠️  ЕСТЬ ПРЕДУПРЕЖДЕНИЯ, НО КРИТИЧЕСКИХ ОШИБОК НЕТ${NC}"
        return 0
    else
        echo -e "${RED}❌ ОБНАРУЖЕНЫ КРИТИЧЕСКИЕ ОШИБКИ!${NC}"
        echo ""
        echo "Рекомендации:"
        echo "1. Исправьте все критические ошибки (FAIL)"
        echo "2. Рассмотрите предупреждения (WARN)"
        echo "3. Запустите тесты: cd test_build && ctest"
        return 1
    fi
}

# Главная функция
main() {
    echo "╔════════════════════════════════════════════════════════════╗"
    echo "║  UTXO CLI Commands Verification Tool                      ║"
    echo "║  Cellframe SDK                                            ║"
    echo "╚════════════════════════════════════════════════════════════╝"
    
    check_files_exist
    check_cli_parameters
    check_utxo_format
    check_flags
    check_tsd_types
    check_test_coverage
    check_use_cases
    check_error_handling
    
    print_summary
}

# Запускаем главную функцию
main "$@"

