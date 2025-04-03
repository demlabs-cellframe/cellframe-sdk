#ifndef __MSRLN_H__
#define __MSRLN_H__


// For C++
#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include "dap_crypto_common.h"

// Definitions of the error-handling type and error codes

typedef enum {
    CRYPTO_MSRLN_SUCCESS,                          // 0x00
    CRYPTO_MSRLN_ERROR,                            // 0x01
    CRYPTO_MSRLN_ERROR_DURING_TEST,                // 0x02
    CRYPTO_MSRLN_ERROR_UNKNOWN,                    // 0x03
    CRYPTO_MSRLN_ERROR_NOT_IMPLEMENTED,            // 0x04
    CRYPTO_MSRLN_ERROR_NO_MEMORY,                  // 0x05
    CRYPTO_MSRLN_ERROR_INVALID_PARAMETER,          // 0x06
    CRYPTO_MSRLN_ERROR_SHARED_KEY,                 // 0x07
    CRYPTO_MSRLN_ERROR_TOO_MANY_ITERATIONS,        // 0x08
    CRYPTO_MSRLN_ERROR_END_OF_LIST
} CRYPTO_MSRLN_STATUS;

#define CRYPTO_STATUS_TYPE_SIZE (CRYPTO_MSRLN_ERROR_END_OF_LIST)


// Definitions of the error messages
// NOTE: they must match the error codes above

#define CRYPTO_MSG_SUCCESS                                "CRYPTO_SUCCESS"
#define CRYPTO_MSG_ERROR                                  "CRYPTO_ERROR"
#define CRYPTO_MSG_ERROR_DURING_TEST                      "CRYPTO_ERROR_DURING_TEST"
#define CRYPTO_MSG_ERROR_UNKNOWN                          "CRYPTO_ERROR_UNKNOWN"
#define CRYPTO_MSG_ERROR_NOT_IMPLEMENTED                  "CRYPTO_ERROR_NOT_IMPLEMENTED"
#define CRYPTO_MSG_ERROR_NO_MEMORY                        "CRYPTO_ERROR_NO_MEMORY"
#define CRYPTO_MSG_ERROR_INVALID_PARAMETER                "CRYPTO_ERROR_INVALID_PARAMETER"
#define CRYPTO_MSG_ERROR_SHARED_KEY                       "CRYPTO_ERROR_SHARED_KEY"
#define CRYPTO_MSG_ERROR_TOO_MANY_ITERATIONS              "CRYPTO_ERROR_TOO_MANY_ITERATIONS"                                                            


// Definition of type "RandomBytes" to implement callback function outputting "nbytes" of random values to "random_array"
typedef CRYPTO_MSRLN_STATUS (*RandomBytes)(unsigned char* random_array, unsigned int nbytes);

// Definition of type "ExtendableOutput" to implement callback function outputting 32-bit "array_ndigits" of values to "extended_array"
typedef CRYPTO_MSRLN_STATUS (*ExtendableOutput)(const unsigned char* seed, unsigned int seed_nbytes, unsigned int array_ndigits, uint32_t* extended_array);

// Definition of type "StreamOutput" to implement callback function outputting 32-bit "array_ndigits" of values to "stream_array"
typedef CRYPTO_MSRLN_STATUS (*StreamOutput)(const unsigned char* seed, unsigned int seed_nbytes, unsigned char* nonce, unsigned int nonce_nbytes, unsigned int array_nbytes, unsigned char* stream_array);


// Basic key-exchange constants  
#define MSRLN_PKA_BYTES           1824      // Alice's public key size
#define MSRLN_PKB_BYTES           2048      // Bob's public key size
#define MSRLN_SHAREDKEY_BYTES     32        // Shared key size


// This data struct is initialized during setup with user-provided functions
typedef struct
{
    RandomBytes      RandomBytesFunction;               // Function providing random bytes
    ExtendableOutput ExtendableOutputFunction;          // Extendable output function
    StreamOutput     StreamOutputFunction;              // Stream cipher function
} LatticeCryptoStruct, *PLatticeCryptoStruct;


/******************** Function prototypes *******************/
/*********************** Auxiliary API **********************/ 

// Clear digits from memory. "nwords" indicates the number of digits to be zeroed.
extern void clear_words(void* mem, digit_t nwords);
CRYPTO_MSRLN_STATUS MSRLN_get_error(const unsigned char* seed, unsigned int seed_nbytes, unsigned char* nonce, unsigned int nonce_nbytes, unsigned int array_nbytes, unsigned char* stream_array);
CRYPTO_MSRLN_STATUS MSRLN_generate_a(const unsigned char* seed, unsigned int seed_nbytes, unsigned int array_ndigits, uint32_t* a);

// Output "nbytes" of random values.
// It makes requests of random values to RandomBytesFunction. If successful, the output is given in "random_array".
// The caller is responsible for providing the "RandomBytesFunction" function passing random value as octets.
CRYPTO_MSRLN_STATUS random_bytes(unsigned int nbytes, unsigned char* random_array, RandomBytes RandomBytesFunction);

// Output "array_ndigits" of values in [0, q-1] using an extendable-output function and a seed of size "seed_nbytes".   
// It makes requests of values to ExtendableOutputFunction. If successful, the output is given in "extended_array".
// The caller is responsible for providing the "ExtendableOutputFunction" function passing values as 32-bit digits. 
CRYPTO_MSRLN_STATUS extended_output(const unsigned char* seed, unsigned int seed_nbytes, unsigned int array_ndigits, uint32_t* extended_array, ExtendableOutput ExtendableOutputFunction);

// Output "array_nbytes" of values using a stream cipher, a seed of size "seed_nbytes" and a nonce of size "nonce_nbytes".  
// It makes requests of values to StreamOutputFunction. If successful, the output is given in "stream_array".
// The caller is responsible for providing the "StreamOutputFunction" function passing values as octets.  
CRYPTO_MSRLN_STATUS stream_output(const unsigned char* seed, unsigned int seed_nbytes, unsigned char* nonce, unsigned int nonce_nbytes, unsigned int array_nbytes, unsigned char* stream_array, StreamOutput StreamOutputFunction);

// Dynamic allocation of memory for LatticeCrypto structure. It should be called before initialization with LatticeCrypto_initialize(). Returns NULL on error.
PLatticeCryptoStruct LatticeCrypto_allocate(void); 

// Initialize structure pLatticeCrypto with user-provided functions: RandomBytesFunction, ExtendableOutputFunction and StreamOutputFunction.
CRYPTO_MSRLN_STATUS LatticeCrypto_initialize(PLatticeCryptoStruct pLatticeCrypto, RandomBytes RandomBytesFunction, ExtendableOutput ExtendableOutputFunction, StreamOutput StreamOutputFunction);

// Output error/success message for a given CRYPTO_STATUS
const char* LatticeCrypto_get_error_message(CRYPTO_MSRLN_STATUS Status);

/*********************** Key exchange API ***********************/ 

// Alice's key generation 
// It produces a private key SecretKeyA and computes the public key PublicKeyA.
// Outputs: the private key SecretKeyA that consists of a 32-bit signed 1024-element array (4096 bytes in total)
//          the public key PublicKeyA that occupies 1824 bytes
// pLatticeCrypto must be set up in advance using LatticeCrypto_initialize().
CRYPTO_MSRLN_STATUS MSRLN_KeyGeneration_A(int32_t* SecretKeyA, unsigned char* PublicKeyA, PLatticeCryptoStruct pLatticeCrypto);

// Bob's key generation and shared secret computation
// It produces a private key and computes the public key PublicKeyB. In combination with Alice's public key PublicKeyA, it computes 
// the shared secret SharedSecretB.
// Input:   Alice's public key PublicKeyA that consists of 1824 bytes
// Outputs: the public key PublicKeyB that occupies 2048 bytes.
//          the 256-bit shared secret SharedSecretB.
// pLatticeCrypto must be set up in advance using LatticeCrypto_initialize().
CRYPTO_MSRLN_STATUS MSRLN_SecretAgreement_B(unsigned char* PublicKeyA, unsigned char* SharedSecretB, unsigned char* PublicKeyB, PLatticeCryptoStruct pLatticeCrypto);

// Alice's shared secret computation 
// It computes the shared secret SharedSecretA using Bob's public key PublicKeyB and Alice's private key SecretKeyA.
// Inputs: Bob's public key PublicKeyB that consists of 2048 bytes
//         the private key SecretKeyA that consists of a 32-bit signed 1024-element array (4096 bytes in total)
// Output: the 256-bit shared secret SharedSecretA.
// pLatticeCrypto must be set up in advance using LatticeCrypto_initialize().
CRYPTO_MSRLN_STATUS MSRLN_SecretAgreement_A(unsigned char* PublicKeyB, int32_t* SecretKeyA, unsigned char* SharedSecretA);


#ifdef __cplusplus
}
#endif


#endif
