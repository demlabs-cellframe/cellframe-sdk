cmake_minimum_required(VERSION 3.10)
project(cellframe_sdk_hello_world)

# Найти CellFrame SDK
find_package(CellFrame REQUIRED)

# Создать исполняемый файл
add_executable(hello_cellframe main.c)

# Подключить CellFrame SDK
target_link_libraries(hello_cellframe cellframe_core cellframe_chain)

# Установить свойства
set_target_properties(hello_cellframe PROPERTIES
    C_STANDARD 11
    C_STANDARD_REQUIRED ON
)

# Установка
install(TARGETS hello_cellframe
    RUNTIME DESTINATION bin
)
