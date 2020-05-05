/** @file 
 * @brief Объявление функций реализующих преобразования из алгоритма "Кузнечик"
 *
 * @copyright InfoTeCS. All rights reserved.
 */

/** @brief file guard */
#ifndef DLL_IMPORT_H
#define DLL_IMPORT_H
 

#ifdef WIN32
     #define DLL_IMPORT __stdcall//__fastcall//
#else
     #define DLL_IMPORT
#endif

#endif
