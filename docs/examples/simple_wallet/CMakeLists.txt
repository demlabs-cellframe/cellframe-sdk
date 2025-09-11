cmake_minimum_required(VERSION 3.10)
project(simple_wallet C)

# Пути к CellFrame SDK (относительно директории примера)
set(CELLFRAME_SDK_ROOT "../../../../..")

# Создать исполняемый файл
add_executable(${PROJECT_NAME}
    main.c
)

# Включить директории CellFrame SDK
target_include_directories(${PROJECT_NAME} PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CELLFRAME_SDK_ROOT}/modules/common/include
    ${CELLFRAME_SDK_ROOT}/modules/wallet/include
    ${CELLFRAME_SDK_ROOT}/dap-sdk/core/include
    ${CELLFRAME_SDK_ROOT}/dap-sdk/crypto/include
)

# Найти и подключить библиотеки
find_library(CELLFRAME_COMMON_LIBRARY dap_common PATHS ${CELLFRAME_SDK_ROOT}/build/dap-sdk/core)
find_library(CELLFRAME_WALLET_LIBRARY cellframe-wallet PATHS ${CELLFRAME_SDK_ROOT}/build/modules/wallet)
find_library(DAP_CORE_LIBRARY dap_core PATHS ${CELLFRAME_SDK_ROOT}/build/dap-sdk/core)
find_library(DAP_CRYPTO_LIBRARY dap_crypto PATHS ${CELLFRAME_SDK_ROOT}/build/dap-sdk/crypto)

if(CELLFRAME_COMMON_LIBRARY AND CELLFRAME_WALLET_LIBRARY)
    target_link_libraries(${PROJECT_NAME}
        ${CELLFRAME_WALLET_LIBRARY}
        ${CELLFRAME_COMMON_LIBRARY}
        ${DAP_CRYPTO_LIBRARY}
        ${DAP_CORE_LIBRARY}
        pthread
        m
        json-c
    )
else()
    # Если библиотеки не найдены, попробуем собрать с исходников
    message(WARNING "Pre-built CellFrame libraries not found, trying to build from source")

    # Добавить исходные файлы
    target_sources(${PROJECT_NAME} PRIVATE
        ${CELLFRAME_SDK_ROOT}/modules/common/src/dap_chain_common.c
        ${CELLFRAME_SDK_ROOT}/modules/wallet/src/dap_chain_wallet.c
        ${CELLFRAME_SDK_ROOT}/dap-sdk/core/src/dap_common.c
        ${CELLFRAME_SDK_ROOT}/dap-sdk/crypto/src/dap_enc_key.c
    )

    target_link_libraries(${PROJECT_NAME}
        pthread
        m
        json-c
    )
endif()

# Опции компиляции
target_compile_options(${PROJECT_NAME} PRIVATE
    -Wall
    -Wextra
    -Wpedantic
    -O2
    -g
    -DDAP_OS_LINUX
)

# Установка
install(TARGETS ${PROJECT_NAME}
    RUNTIME DESTINATION bin
)

# Вывод информации о сборке
message(STATUS "CellFrame SDK Simple Wallet Example configured:")
message(STATUS "  CellFrame SDK Root: ${CELLFRAME_SDK_ROOT}")
message(STATUS "  Build type: ${CMAKE_BUILD_TYPE}")
message(STATUS "  Install prefix: ${CMAKE_INSTALL_PREFIX}")
