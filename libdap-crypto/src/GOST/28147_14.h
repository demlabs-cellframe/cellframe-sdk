/** @file 
 * @brief ���������� ������� ����������� �������������� �� ��������� "��������"
 *
 * @copyright InfoTeCS. All rights reserved.
 */

#ifndef C_28147_14_H
#define C_28147_14_H

#include "dll_import.h"
#include "callback_print.h"


#ifdef __cplusplus
extern "C" {
#endif

/** @brief �������������� X
 *
 * @param[in] a ������� �������� ��������������
 * @param[in] b ������� �������� ��������������
 * @param[out] outdata ��������� �������� ��������������
 * @param[in] print ������� �����������
 * @return 0 ���� ��� �������������� ������ �������
 * @return -1 ���� ��������� ������
 */
int DLL_IMPORT funcX(unsigned char* a, unsigned char* b, unsigned char* outdata, printout_byte_array print);

/** @brief �������������� S
 * 
 * @param[in] indata ������� �������� ��������������
 * @param[out] outdata ��������� �������� ��������������
 * @param[in] print ������� �����������
 * @return 0 ���� ��� �������������� ������ �������
 * @return -1 ���� ��������� ������
 */
int DLL_IMPORT funcS(unsigned char* indata, unsigned char* outdata, printout_byte_array print);

/** @brief �������������� �������� � ��������������  S
 * 
 * @param[in] indata ������� �������� ��������������
 * @param[out] outdata ��������� �������� ��������������
 * @param[in] print ������� �����������
 * @return 0 ���� ��� �������������� ������ �������
 * @return -1 ���� ��������� ������
 */
int DLL_IMPORT funcReverseS(unsigned char* indata, unsigned char*  outdata, printout_byte_array print);

/** @brief �������������� R
 * 
 * @param[in] indata ������� �������� ��������������
 * @param[out] outdata ��������� �������� ��������������
 * @param[in] print ������� �����������
 * @return 0 ���� ��� �������������� ������ �������
 * @return -1 ���� ��������� ������
 */
int DLL_IMPORT funcR(unsigned char* indata, unsigned char* outdata, printout_byte_array print);

/** @brief �������������� �������� � ��������������  R
 * 
 * @param[in] indata ������� �������� ��������������
 * @param[out] outdata ��������� �������� ��������������
 * @param[in] print ������� �����������
 * @return 0 ���� ��� �������������� ������ �������
 * @return -1 ���� ��������� ������
 */
int DLL_IMPORT funcReverseR(unsigned char* indata, unsigned char* outdata, printout_byte_array print);

/** @brief �������������� L
 * 
 * @param[in] indata ������� �������� ��������������
 * @param[out] outdata ��������� �������� ��������������
 * @param[in] print ������� �����������
 * @return 0 ���� ��� �������������� ������ �������
 * @return -1 ���� ��������� ������
 */
int DLL_IMPORT funcL(unsigned char* indata, unsigned char* outdata, printout_byte_array print);

/** @brief �������������� �������� � ��������������  L
 * 
 * @param[in] indata ������� �������� ��������������
 * @param[out] outdata ��������� �������� ��������������
 * @param[in] print ������� �����������
 * @return 0 ���� ��� �������������� ������ �������
 * @return -1 ���� ��������� ������
 */
int DLL_IMPORT funcReverseL(unsigned char* indata, unsigned char* outdata, printout_byte_array print);

/** @brief �������������� LSX
 * 
 * @param[in] a ������� �������� ��������������
 * @param[in] b ������� �������� ��������������
 * @param[out] outdata ��������� �������� ��������������
 * @param[in] print ������� �����������
 * @return 0 ���� ��� �������������� ������ �������
 * @return -1 ���� ��������� ������
 */
int DLL_IMPORT funcLSX(unsigned char* a, unsigned char* b, unsigned char* outdata, printout_byte_array print);

/** @brief �������������� �������� � ��������������  LSX
 * 
 * @param[in] a ������� �������� ��������������
 * @param[in] b ������� �������� ��������������
 * @param[out] outdata ��������� �������� ��������������
 * @param[in] print ������� �����������
 * @return 0 ���� ��� �������������� ������ �������
 * @return -1 ���� ��������� ������
 */
int DLL_IMPORT funcReverseLSX(unsigned char* a, unsigned char* b, unsigned char* outdata, printout_byte_array print);

/** @brief �������������� F
 * 
 * @param[in] inputKey ������ ����  �� ���� ������ ���������� � ���������� ��������
 * @param[in] inputKeySecond ������ ����  �� ���� ������ ���������� � ���������� ��������
 * @param[in] iterationConst ������������ ���������
 * @param[out] outputKey ������ ����
 * @param[out] outputKeySecond ������ ����
 * @param[in] print ������� �����������
 * @return 0 ���� ��� �������������� ������ �������
 * @return -1 ���� ��������� ������
 */
int DLL_IMPORT funcF(unsigned char* inputKey, unsigned char* inputKeySecond, unsigned char* iterationConst, unsigned char* outputKey, unsigned char* outputKeySecond, printout_byte_array print);

/** @brief ���������� ������������ ��������� � 
 * 
 * @param[in] number ����� ���������
 * @param[out] output ������������ ���������
 * @param[in] print ������� �����������
 * @return 0 ���� ��� �������������� ������ �������
 * @return -1 ���� ��������� ������
 */
int DLL_IMPORT funcC(unsigned char number, unsigned char* output, printout_byte_array print);

/** @brief ��������� �����
 * 
 * @param[in] masterKey ������ ����
 * @param[out] keys ������ ����������� ������
 * @param[in] print ������� �����������
 * @return 0 ���� ��� �������������� ������ �������
 * @return -1 ���� ��������� ������
 */
int DLL_IMPORT ExpandKey(unsigned char* masterKey, unsigned char* keys, printout_byte_array print);

/** @brief ���������� ������������ �����
 * 
 * @param[in] plainText �������� ����
 * @param[out] chipherText ������������� ����
 * @param[in] keys ����������� �����
 * @param[in] print ������� �����������
 * @param[in] print_uint ������� �����������
 * @return 0 ���� ��� �������������� ������ �������
 * @return -1 ���� ��������� ������
 */
int DLL_IMPORT Encrypt_14(unsigned char* plainText, unsigned char* chipherText, unsigned char* keys, printout_byte_array print, printout_uint_array print_uint);

/** @brief ��������� ������������� �����
 * 
 * @param[in] chipherText ������������� ����
 * @param[out] plainText �������������� ����
 * @param[in] keys ����������� �����
 * @param[in] print ������� �����������
 * @param[in] print_uint ������� �����������
 * @return 0 ���� ��� �������������� ������ �������
 * @return -1 ���� ��������� ������
 */
int DLL_IMPORT Decrypt_14(unsigned char* chipherText, unsigned char* plainText, unsigned char* keys, printout_byte_array print, printout_uint_array print_uint);

#ifdef __cplusplus
}
#endif

#endif
