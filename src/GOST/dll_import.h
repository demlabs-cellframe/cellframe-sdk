/** @file 
 * @brief ���������� ������� ����������� �������������� �� ��������� "��������"
 *
 * @copyright InfoTeCS. All rights reserved.
 */

/** @brief file guard */
#ifndef DLL_IMPORT_H
#define DLL_IMPORT_H
 

#ifdef WIN32
     #define DLL_IMPORT __stdcall
#else
     #define DLL_IMPORT __attribute__((stdcall))
#endif

#endif
