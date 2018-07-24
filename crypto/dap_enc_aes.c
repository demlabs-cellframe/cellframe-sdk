#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "liboqs/crypto/rand/rand.h"
#include "dap_enc_aes.h"
#include "dap_enc_key.h"


#define AES_BLOCKSIZE 16
#define AES_KEYSIZE 16

#define DAP_ENC_AES_KEY(a) ((dap_enc_aes_key_t *)((a)->_inheritor) )

static void print_bytes(uint8_t *bytes, size_t num_bytes) {
	for (size_t i = 0; i < num_bytes; i++) {
		printf("%02x", (unsigned) bytes[i]);
	}
}

/**
 * @brief dap_enc_aes_key_delete
 * @param a_key
 */

int test_key_aes(){
    OQS_RAND *rand = OQS_RAND_new(OQS_RAND_alg_urandom_chacha20);
    uint8_t key[16], plaintext[16], ciphertext[16], decrypted[16];
	void *schedule = NULL;
	OQS_RAND_n(rand, key, 16);
	OQS_RAND_n(rand, plaintext, 16);
	oqs_aes128_load_schedule_c(key, &schedule);
	oqs_aes128_enc_c(plaintext, schedule, ciphertext);
	oqs_aes128_dec_c(ciphertext, schedule, decrypted);
	oqs_aes128_free_schedule_c(schedule);
	if (memcmp(plaintext, decrypted, 16) == 0) {
		return EXIT_SUCCESS;
	} else {
		print_bytes(plaintext, 16);
		printf("\n");
		print_bytes(decrypted, 16);
		printf("\n");
		return EXIT_FAILURE;
	}
}

void dap_enc_aes_key_delete(struct dap_enc_key *a_key)
{
    (void)a_key;
    //No need any specific actions
}

/**
 * @brief dap_enc_aes_key_new_generate
 * @param a_key
 * @param a_size
 */
void dap_enc_aes_key_new_generate(struct dap_enc_key * a_key,size_t a_size)
{
    (void)a_size;
	uint8_t key[AES_KEYSIZE];
	OQS_RAND *rand = OQS_RAND_new(OQS_RAND_alg_urandom_chacha20);
	OQS_RAND_n(rand, key, AES_KEYSIZE);

    a_key->last_used_timestamp = time(NULL);
	a_key->data = (unsigned char*)malloc(AES_KEYSIZE);
	memcpy(a_key->data,&key,AES_KEYSIZE);
	a_key->data_size = sizeof(key);
    a_key->type=DAP_ENC_KEY_TYPE_AES;
    a_key->enc=dap_enc_aes_encode;
    a_key->dec=dap_enc_aes_decode;
    a_key->delete_callback=dap_enc_aes_key_delete;
}

/**
 * @brief dap_enc_aes_key_new_from_data
 * @param a_key
 * @param a_in
 * @param a_in_size
 */
void dap_enc_aes_key_new_from_data(struct dap_enc_key * a_key, const void * a_in, size_t a_in_size)
{
	if(a_in_size < AES_KEYSIZE)
		return;

    a_key->last_used_timestamp = time(NULL);
	a_key->data = (unsigned char*)malloc(AES_KEYSIZE);
	memcpy(a_key->data,a_in,AES_KEYSIZE);
	//a_key->data[16]='\0';
	a_key->data_size = AES_KEYSIZE;
    a_key->type=DAP_ENC_KEY_TYPE_AES;
    a_key->enc=dap_enc_aes_encode;
    a_key->dec=dap_enc_aes_decode;
    a_key->delete_callback=dap_enc_aes_key_delete;
}

/**
 * @brief dap_enc_aes_key_new_from_str
 * @param a_key
 * @param a_in
 * @param a_in_size
 */
void dap_enc_aes_key_new_from_str(struct dap_enc_key * a_key, const char * a_in)
{
	if(strlen(a_in) < AES_KEYSIZE)
		return;

    a_key->last_used_timestamp = time(NULL);
	a_key->data = (unsigned char*)malloc(AES_KEYSIZE);
	memcpy(a_key->data,a_in,AES_KEYSIZE);
	//a_key->data[16]='\0';
	a_key->data_size = AES_KEYSIZE;
    a_key->type=DAP_ENC_KEY_TYPE_AES;
    a_key->enc=dap_enc_aes_encode;
    a_key->dec=dap_enc_aes_decode;
    a_key->delete_callback=dap_enc_aes_key_delete;
}


/**
 * @brief dap_enc_aes_decode
 * @param a_key
 * @param a_in
 * @param a_in_size
 * @param a_out
 * @return
 */
size_t dap_enc_aes_decode(struct dap_enc_key* a_key, const void * a_in, size_t a_in_size,void * a_out)
{
	if(a_in_size % 16 != 0)
		return 0;
    OQS_AES128_ECB_dec(a_in,a_in_size,a_key->data,a_out);
    int tail = 0;
	size_t end = a_in_size-16 > 0 ? a_in_size-16 : 0;
    for(size_t i =a_in_size-1; i >= end; i--)
	{
        if(*(char*)(a_out + i) == (char)0)
			tail++;
		else
			break;  
	}
	return a_in_size - tail;
}

/**
 * @brief dap_enc_aes_encode
 * @param a_key
 * @param a_in
 * @param a_in_size
 * @param a_out
 * @return
 */
size_t dap_enc_aes_encode(struct dap_enc_key* a_key, const void * a_in, size_t a_in_size,void * a_out)
{
    int tail = 0;
    if(a_in_size < 16)
        tail = 16 - a_in_size;
    else if(a_in_size%16 > 0)
        tail = 16 - a_in_size % 16;
    void * a_in_new = (void*)malloc(a_in_size + tail);
    memcpy(a_in_new,a_in,a_in_size);
    memset(a_in_new+a_in_size,0,tail);
    OQS_AES128_ECB_enc(a_in_new,a_in_size+tail,a_key->data,a_out);
	free(a_in_new);
    return a_in_size + tail;
}
