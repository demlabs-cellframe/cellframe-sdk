/** @file 
 * @brief ���������� ������� ������ ���������� �� �����
 *
 * @copyright InfoTeCS. All rights reserved.
 */

#ifndef PRINT_DATA_H
#define PRINT_DATA_H

#include "dll_import.h"

/** @brief ������ ��������� ������ � �������� */
#define LINE_WIDTH 60

/** @brief ����� ��������� � �������� */
#define TAB_WIDTH 4

/** @brief ������� ���������� �����
 *
 * @param[in] caption ��������� �����
 * @param[in] result ��������� �����
 */
int PrintTest(const char* caption, int result);

/** @brief ������� ������ */
void PrintCharSingle(char c);

/** @brief ������� ����������� ������ c count ��� */
void PrintChar(char c, size_t count);

/** @brief ������� ������ ��������������� ����� */
void PrintStr(const char* s);

/** @brief ������� ������ ��������������� ����� �������� �� ��������� �� ��������� ������ */
void PrintStrAlign(const char* s, size_t width);

/** @brief ������� ������ ��������������� ����� � ��������� ������� �� ��������� ������ */
void PrintLine(const char* line);

/** @brief ��������� ������� �� ��������� ������ */
void PrintEmptyLine();

/** @brief ������� ������ ������ ������ ������ � ����� �� �������� ���������� ������� */
void PrintLineLeft(const char* label);

/** @brief ������� ������ ����������� */
void PrintSplitLine();

/** @brief ������� �����������, ������ � ��������� ������� �� ��������� ������  */
void PrintLabel(const char* label);

/** @brief ������� ���� ���� � HEX ������������� */
void PrintHex(unsigned char value);

/** @brief ������� ������ ���� � HEX ������������� */
void PrintHexArray(unsigned char* value, size_t size);

/** @brief ������� int32 ����� � HEX ������������� */
void PrintUInt32(unsigned int d);

/** @brief ������� ���� ������ */
void PrintBlock(const char* label, unsigned char* value, size_t valueSize, size_t blockSize);

/** @brief ������� ���� ������ */
void PrintBlockInt(const char* label, unsigned int value);

/** @brief ������� ���� ������  */
void PrintBlockLeft(const char* label, unsigned int value);

/** @brief callback ��� ������ ������� byte */
void DLL_IMPORT print_array(const char* label, unsigned char* value, unsigned int valueSize);

/** @brief callback ��� ������ ������� unsigned int32 */
void DLL_IMPORT print_uint_array(const char* label, unsigned int* value, unsigned int valueSize);

#endif
