/** @file 
 * @brief Объявление функций реализующих преобразования из алгоритма "28147-89"
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

/** @brief Функция подстановки
 *
 * @param[in] a входной параметр преобразования
 * @param[in] print функция логирования
 * @return результат преобразования
 */
unsigned int DLL_IMPORT funcT(unsigned int a, printout_uint_array print);

/** @brief Преобразование g Из стандарта
 *
 * @param[in] a входной параметр преобразования
 * @param[in] k ключ
 * @param[in] print функция логирования
 * @return результат преобразования
 */
unsigned int DLL_IMPORT funcG(unsigned int a, unsigned int k, printout_uint_array print);

/** @brief Преобразование G Из стандарта
 *
 * @param[out] a1 указатель на буфер, где хранятся данные и куда будет записан результат 
 * @param[out] a0 указатель на буфер, где хранятся данные и куда будет записан результат 
 * @param[in] k ключ
 * @param[in] print функция логирования
 */
void DLL_IMPORT Round(unsigned int* a1, unsigned int* a0, unsigned int k, printout_uint_array print);

/** @brief Преобразование G Из стандарта ( не меняя блоки а1 и а0 местами )
 *
 * @param[out] a1 указатель на буфер, где хранятся данные и куда будет записан результат 
 * @param[out] a0 указатель на буфер, где хранятся данные и куда будет записан результат 
 * @param[in] k ключ
 * @param[in] print функция логирования
 */
void DLL_IMPORT RoundShtrih(unsigned int *a1, unsigned int *a0, unsigned int k, printout_uint_array print);

/** @brief Базовое криптографическое преобразование
 *
 * @param[in] input - сообщение с длиною равной длине блока данных
 * @param[out] output - результат операции
 * @param[in] key ключ
 * @param[in] keySequence последовательность применения ключей
 * @param[in] print функция логирования
 * @return 0 если все преобразование прошло успешно
 * @return -1 если произошла ошибка
 */
int DLL_IMPORT CryptBlock(const unsigned char* input, unsigned char* output, unsigned char* key, unsigned char* keySequence, printout_uint_array print);

/** @brief Шифруем блок данных
 *
 * @param[in] input - блок данных открытый текст
 * @param[out] output - зашифрованный блок данных
 * @param[in] key ключ
 * @param[in] print функция логирования
 * @return 0 если все преобразование прошло успешно
 * @return -1 если произошла ошибка
 */
int DLL_IMPORT EncryptBlock(const unsigned char* input, unsigned char* output, unsigned char* key, printout_uint_array print);

/** @brief Расшифровываем блок данных
 *
 * @param[in] input - зашифрованный блок данных
 * @param[out] output - расшифрованный блок данных
 * @param[in] key ключ
 * @param[in] print функция логирования
 * @return 0 если все преобразование прошло успешно
 * @return -1 если произошла ошибка
 */
int DLL_IMPORT DecryptBlock(const unsigned char* input, unsigned char* output, unsigned char* key, printout_uint_array print);

/** @brief Шифруем блок данных
 *
 * @param[in] input - блок данных открытый текст
 * @param[out] output - зашифрованный блок данных
 * @param[in] key ключ
 * @param[in] print функция логирования
 * @param[in] print_uint функция логирования
 * @return 0 если все преобразование прошло успешно
 * @return -1 если произошла ошибка
 */
int DLL_IMPORT Encrypt_89(const unsigned char* input, unsigned char* output, unsigned char* key, printout_byte_array print, printout_uint_array print_uint);

/** @brief Расшифровываем блок данных
 *
 * @param[in] input - зашифрованный блок данных
 * @param[out] output - расшифрованный блок данных
 * @param[in] key ключ
 * @param[in] print функция логирования
 * @param[in] print_uint функция логирования
 * @return 0 если все преобразование прошло успешно
 * @return -1 если произошла ошибка
 */
int DLL_IMPORT Decrypt_89(const unsigned char* input, unsigned char* output, unsigned char* key, printout_byte_array print, printout_uint_array print_uint);

#ifdef __cplusplus
}
#endif

#endif
