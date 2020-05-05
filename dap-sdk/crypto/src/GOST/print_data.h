/** @file 
 * @brief Объявление функций вывода информации на экран
 *
 * @copyright InfoTeCS. All rights reserved.
 */

#ifndef PRINT_DATA_H
#define PRINT_DATA_H

#include "dll_import.h"

/** @brief ширина выводимой строки в символах */
#define LINE_WIDTH 60

/** @brief длина табуляции в символах */
#define TAB_WIDTH 4

/** @brief Выводит результаты теста
 *
 * @param[in] caption заголовок теста
 * @param[in] result результат теста
 */
int PrintTest(const char* caption, int result);

/** @brief Выводит символ */
void PrintCharSingle(char c);

/** @brief Выводит повторяющий символ c count раз */
void PrintChar(char c, size_t count);

/** @brief Выводит строку заканчивающуюся нулем */
void PrintStr(const char* s);

/** @brief Выводит строку заканчивающуюся нулем дополняя ее пробелами до заданнной ширины */
void PrintStrAlign(const char* s, size_t width);

/** @brief Выводит строку заканчивающуюся нулем и переводит коретку на следующую строку */
void PrintLine(const char* line);

/** @brief Переводит коретку на следующую строку */
void PrintEmptyLine();

/** @brief Выводит строку смещяя начало строки в право на заданное количество позиций */
void PrintLineLeft(const char* label);

/** @brief Выводит строку разделитель */
void PrintSplitLine();

/** @brief Выводит разделитель, строку и переводит коретку на следующую строку  */
void PrintLabel(const char* label);

/** @brief Выводит один байт в HEX представлении */
void PrintHex(unsigned char value);

/** @brief Выводит массив байт в HEX представлении */
void PrintHexArray(unsigned char* value, size_t size);

/** @brief Выводит int32 число в HEX представлении */
void PrintUInt32(unsigned int d);

/** @brief Выводит блок данных */
void PrintBlock(const char* label, unsigned char* value, size_t valueSize, size_t blockSize);

/** @brief Выводит блок данных */
void PrintBlockInt(const char* label, unsigned int value);

/** @brief Выводит блок данных  */
void PrintBlockLeft(const char* label, unsigned int value);

/** @brief callback для вывода массива byte */
void DLL_IMPORT print_array(const char* label, unsigned char* value, unsigned int valueSize);

/** @brief callback для вывода массива unsigned int32 */
void DLL_IMPORT print_uint_array(const char* label, unsigned int* value, unsigned int valueSize);

#endif
