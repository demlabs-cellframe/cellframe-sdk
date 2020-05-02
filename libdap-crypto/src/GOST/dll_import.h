/** @file 
 * @brief ќбъ€вление функций реализующих преобразовани€ из алгоритма " узнечик"
 *
 * @copyright InfoTeCS. All rights reserved.
 */

/** @brief file guard */
#ifndef DLL_IMPORT_H
#define DLL_IMPORT_H
 

#ifdef WIN32
     #define DLL_IMPORT __stdcall
#else
     #define DLL_IMPORT
#endif

#endif
