/** @file 
 * @brief Объявление callback функций реализующих вывод информации
 *
 * @copyright InfoTeCS. All rights reserved.
 */

#ifndef CALLBACK_PRINT_H
#define CALLBACK_PRINT_H

#include "dll_import.h"

/** @brief callback для вывода массива byte */
typedef void (DLL_IMPORT *printout_byte_array)(const char* text, const unsigned char* value, unsigned int valueSize);

/** @brief callback для вывода массива unsigned int32 */
typedef void (DLL_IMPORT *printout_uint_array)(const char* text, const unsigned int* value, unsigned int valueSize);

#endif
