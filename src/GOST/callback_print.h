/** @file 
 * @brief ќбъ€вление callback функций реализующих вывод информации
 *
 * @copyright InfoTeCS. All rights reserved.
 */

#ifndef CALLBACK_PRINT_H
#define CALLBACK_PRINT_H

#include "dll_import.h"

/** @brief callback дл€ вывода массива byte */
typedef void (DLL_IMPORT *printout_byte_array)(const char* text, unsigned char* value, unsigned int valueSize);

/** @brief callback дл€ вывода массива unsigned int32 */
typedef void (DLL_IMPORT *printout_uint_array)(const char* text, unsigned int* value, unsigned int valueSize);

#endif
