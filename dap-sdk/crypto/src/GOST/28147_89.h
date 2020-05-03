/** @file 
 * @brief ���������� ������� ����������� �������������� �� ��������� "28147-89"
 *
 * @copyright InfoTeCS. All rights reserved.
 */

#ifndef C_28147_89_H
#define C_28147_89_H

#include "dll_import.h"
#include "callback_print.h"

#ifdef __cplusplus
extern "C" {
#endif

/** @brief ������� �����������
 *
 * @param[in] a ������� �������� ��������������
 * @param[in] print ������� �����������
 * @return ��������� ��������������
 */
unsigned int DLL_IMPORT funcT(unsigned int a, printout_uint_array print);

/** @brief �������������� g �� ���������
 *
 * @param[in] a ������� �������� ��������������
 * @param[in] k ����
 * @param[in] print ������� �����������
 * @return ��������� ��������������
 */
unsigned int DLL_IMPORT funcG(unsigned int a, unsigned int k, printout_uint_array print);

/** @brief �������������� G �� ���������
 *
 * @param[out] a1 ��������� �� �����, ��� �������� ������ � ���� ����� ������� ��������� 
 * @param[out] a0 ��������� �� �����, ��� �������� ������ � ���� ����� ������� ��������� 
 * @param[in] k ����
 * @param[in] print ������� �����������
 */
void DLL_IMPORT Round(unsigned int* a1, unsigned int* a0, unsigned int k, printout_uint_array print);

/** @brief �������������� G �� ��������� ( �� ����� ����� �1 � �0 ������� )
 *
 * @param[out] a1 ��������� �� �����, ��� �������� ������ � ���� ����� ������� ��������� 
 * @param[out] a0 ��������� �� �����, ��� �������� ������ � ���� ����� ������� ��������� 
 * @param[in] k ����
 * @param[in] print ������� �����������
 */
void DLL_IMPORT RoundShtrih(unsigned int *a1, unsigned int *a0, unsigned int k, printout_uint_array print);

/** @brief ������� ����������������� ��������������
 *
 * @param[in] input - ��������� � ������ ������ ����� ����� ������
 * @param[out] output - ��������� ��������
 * @param[in] key ����
 * @param[in] keySequence ������������������ ���������� ������
 * @param[in] print ������� �����������
 * @return 0 ���� ��� �������������� ������ �������
 * @return -1 ���� ��������� ������
 */
int DLL_IMPORT CryptBlock(unsigned char* input, unsigned char* output, unsigned char* key, unsigned char* keySequence, printout_uint_array print);

/** @brief ������� ���� ������
 *
 * @param[in] input - ���� ������ �������� �����
 * @param[out] output - ������������� ���� ������
 * @param[in] key ����
 * @param[in] print ������� �����������
 * @return 0 ���� ��� �������������� ������ �������
 * @return -1 ���� ��������� ������
 */
int DLL_IMPORT EncryptBlock(unsigned char* input, unsigned char* output, unsigned char* key, printout_uint_array print);

/** @brief �������������� ���� ������
 *
 * @param[in] input - ������������� ���� ������
 * @param[out] output - �������������� ���� ������
 * @param[in] key ����
 * @param[in] print ������� �����������
 * @return 0 ���� ��� �������������� ������ �������
 * @return -1 ���� ��������� ������
 */
int DLL_IMPORT DecryptBlock(unsigned char* input, unsigned char* output, unsigned char* key, printout_uint_array print);

/** @brief ������� ���� ������
 *
 * @param[in] input - ���� ������ �������� �����
 * @param[out] output - ������������� ���� ������
 * @param[in] key ����
 * @param[in] print ������� �����������
 * @param[in] print_uint ������� �����������
 * @return 0 ���� ��� �������������� ������ �������
 * @return -1 ���� ��������� ������
 */
int DLL_IMPORT Encrypt_89(unsigned char* input, unsigned char* output, unsigned char* key, printout_byte_array print, printout_uint_array print_uint);

/** @brief �������������� ���� ������
 *
 * @param[in] input - ������������� ���� ������
 * @param[out] output - �������������� ���� ������
 * @param[in] key ����
 * @param[in] print ������� �����������
 * @param[in] print_uint ������� �����������
 * @return 0 ���� ��� �������������� ������ �������
 * @return -1 ���� ��������� ������
 */
int DLL_IMPORT Decrypt_89(unsigned char* input, unsigned char* output, unsigned char* key, printout_byte_array print, printout_uint_array print_uint);

#ifdef __cplusplus
}
#endif

#endif
