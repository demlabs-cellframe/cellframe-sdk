/** @file 
 * @brief Объявление функций реализующих преобразования из алгоритма "Кузнечик"
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

/** @brief Преобразование X
 *
 * @param[in] a входной параметр преобразования
 * @param[in] b входной параметр преобразования
 * @param[out] outdata результат параметр преобразования
 * @param[in] print функция логирования
 * @return 0 если все преобразование прошло успешно
 * @return -1 если произошла ошибка
 */
int DLL_IMPORT funcX(unsigned char* a, unsigned char* b, unsigned char* outdata, printout_byte_array print);

/** @brief Преобразование S
 * 
 * @param[in] indata входной параметр преобразования
 * @param[out] outdata результат параметр преобразования
 * @param[in] print функция логирования
 * @return 0 если все преобразование прошло успешно
 * @return -1 если произошла ошибка
 */
int DLL_IMPORT funcS(unsigned char* indata, unsigned char* outdata, printout_byte_array print);

/** @brief Преобразование обратное к преобразованию  S
 * 
 * @param[in] indata входной параметр преобразования
 * @param[out] outdata результат параметр преобразования
 * @param[in] print функция логирования
 * @return 0 если все преобразование прошло успешно
 * @return -1 если произошла ошибка
 */
int DLL_IMPORT funcReverseS(unsigned char* indata, unsigned char*  outdata, printout_byte_array print);

/** @brief Преобразование R
 * 
 * @param[in] indata входной параметр преобразования
 * @param[out] outdata результат параметр преобразования
 * @param[in] print функция логирования
 * @return 0 если все преобразование прошло успешно
 * @return -1 если произошла ошибка
 */
int DLL_IMPORT funcR(unsigned char* indata, unsigned char* outdata, printout_byte_array print);

/** @brief Преобразование обратное к преобразованию  R
 * 
 * @param[in] indata входной параметр преобразования
 * @param[out] outdata результат параметр преобразования
 * @param[in] print функция логирования
 * @return 0 если все преобразование прошло успешно
 * @return -1 если произошла ошибка
 */
int DLL_IMPORT funcReverseR(unsigned char* indata, unsigned char* outdata, printout_byte_array print);

/** @brief Преобразование L
 * 
 * @param[in] indata входной параметр преобразования
 * @param[out] outdata результат параметр преобразования
 * @param[in] print функция логирования
 * @return 0 если все преобразование прошло успешно
 * @return -1 если произошла ошибка
 */
int DLL_IMPORT funcL(unsigned char* indata, unsigned char* outdata, printout_byte_array print);

/** @brief Преобразование обратное к преобразованию  L
 * 
 * @param[in] indata входной параметр преобразования
 * @param[out] outdata результат параметр преобразования
 * @param[in] print функция логирования
 * @return 0 если все преобразование прошло успешно
 * @return -1 если произошла ошибка
 */
int DLL_IMPORT funcReverseL(unsigned char* indata, unsigned char* outdata, printout_byte_array print);

/** @brief Преобразование LSX
 * 
 * @param[in] a входной параметр преобразования
 * @param[in] b входной параметр преобразования
 * @param[out] outdata результат параметр преобразования
 * @param[in] print функция логирования
 * @return 0 если все преобразование прошло успешно
 * @return -1 если произошла ошибка
 */
int DLL_IMPORT funcLSX(unsigned char* a, unsigned char* b, unsigned char* outdata, printout_byte_array print);

/** @brief Преобразование обратное к преобразованию  LSX
 * 
 * @param[in] a входной параметр преобразования
 * @param[in] b входной параметр преобразования
 * @param[out] outdata результат параметр преобразования
 * @param[in] print функция логирования
 * @return 0 если все преобразование прошло успешно
 * @return -1 если произошла ошибка
 */
int DLL_IMPORT funcReverseLSX(unsigned char* a, unsigned char* b, unsigned char* outdata, printout_byte_array print);

/** @brief Преобразование F
 * 
 * @param[in] inputKey Первый ключ  из пары ключей полученной в предедущей итерации
 * @param[in] inputKeySecond Второй ключ  из пары ключей полученной в предедущей итерации
 * @param[in] iterationConst Итерационная константа
 * @param[out] outputKey Первый ключ
 * @param[out] outputKeySecond Второй ключ
 * @param[in] print функция логирования
 * @return 0 если все преобразование прошло успешно
 * @return -1 если произошла ошибка
 */
int DLL_IMPORT funcF(unsigned char* inputKey, unsigned char* inputKeySecond, unsigned char* iterationConst, unsigned char* outputKey, unsigned char* outputKeySecond, printout_byte_array print);

/** @brief Вычисление итерационной константы С 
 * 
 * @param[in] number номер константы
 * @param[out] output итерационная константа
 * @param[in] print функция логирования
 * @return 0 если все преобразование прошло успешно
 * @return -1 если произошла ошибка
 */
int DLL_IMPORT funcC(unsigned char number, unsigned char* output, printout_byte_array print);

/** @brief Развертка ключа
 * 
 * @param[in] masterKey Мастер ключ
 * @param[out] keys массив развернутых ключей
 * @param[in] print функция логирования
 * @return 0 если все преобразование прошло успешно
 * @return -1 если произошла ошибка
 */
int DLL_IMPORT ExpandKey(unsigned char* masterKey, unsigned char* keys, printout_byte_array print);

/** @brief Выполнение зашифрования блока
 * 
 * @param[in] plainText Исходный блок
 * @param[out] chipherText Зашифрованный блок
 * @param[in] keys Развернутые ключи
 * @param[in] print функция логирования
 * @param[in] print_uint функция логирования
 * @return 0 если все преобразование прошло успешно
 * @return -1 если произошла ошибка
 */
int DLL_IMPORT Encrypt_14(const unsigned char* plainText, unsigned char* chipherText, unsigned char* keys, printout_byte_array print, printout_uint_array print_uint);

/** @brief Выполение расшифрования блока
 * 
 * @param[in] chipherText Зашифрованный блок
 * @param[out] plainText Расшифрованный блок
 * @param[in] keys Развернутые ключи
 * @param[in] print функция логирования
 * @param[in] print_uint функция логирования
 * @return 0 если все преобразование прошло успешно
 * @return -1 если произошла ошибка
 */
int DLL_IMPORT Decrypt_14(const unsigned char* chipherText, unsigned char* plainText, unsigned char* keys, printout_byte_array print, printout_uint_array print_uint);

#ifdef __cplusplus
}
#endif

#endif
