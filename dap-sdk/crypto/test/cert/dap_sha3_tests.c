#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <memory.h>
#include <time.h>
#include <stdbool.h>

#ifdef _WIN32
#include <windows.h>
#endif

#include <pthread.h>

#include "dap_test.h"

#define BUFSIZE 512

#ifdef _MSC_VER
  #define DAP_STATIC_INLINE static __forceinline
  #define DAP_INLINE __forceinline
  #define DAP_ALIGNED(x) __declspec( align(x) )
#else
  #define DAP_STATIC_INLINE static __attribute__((always_inline)) inline
  #define DAP_INLINE __attribute__((always_inline)) inline
  #define DAP_ALIGNED(x) __attribute__ ((aligned (x)))
#endif

uint32_t xs30_seed[4] = { 0x3D696D09, 0xCD6BEB33, 0x9D1A0022, 0x9D1B0022 };

static inline void zRAND_reset( void ) {

  xs30_seed[0] = 0x3D696D09;
  xs30_seed[1] = 0xCD6BEB33;
  xs30_seed[2] = 0x9D1A0022;
  xs30_seed[3] = 0x9D1B0022;
}

static inline uint32_t zRAND( void ) {          //period 2^96-1

  uint32_t *zseed = &xs30_seed[0];

  uint32_t  t;

  zseed[0] ^= zseed[0] << 16;
  zseed[0] ^= zseed[0] >> 5;
  zseed[0] ^= zseed[0] << 1;

  t = zseed[0];
  zseed[0] = zseed[1];
  zseed[1] = zseed[2];

  zseed[2] = t ^ zseed[0] ^ zseed[1];

  return zseed[0];
}

static inline uint64_t gettime64( void )
{
  uint64_t t64;
  struct timespec now;

  clock_gettime( CLOCK_MONOTONIC, &now );
  t64 = now.tv_sec;
  t64 *= 1000000000;
  t64 += now.tv_nsec;

  return t64;
}

static inline double gettimefloat( void )
{
  return (double)gettime64() / 1000000000.0;
}

#include "dap_hash.h"
#include "XKCP/lib/high/Keccak/FIPS202/KeccakHash.h"
#include "fips202.h"
#include "SimpleFIPS202.h"
/*
#define DAP_CHAIN_HASH_FAST_SIZE    32

typedef union dap_chain_hash_fast{
    uint8_t raw[DAP_CHAIN_HASH_FAST_SIZE];
} dap_chain_hash_fast_t;

typedef enum dap_hash_type {
    DAP_HASH_TYPE_KECCAK = 0,
    DAP_HASH_TYPE_SLOW_0 = 1,
} dap_hash_type_t;

static inline void dap_hash_keccak( const void * a_in, size_t a_in_size, void *a_out, size_t a_out_size )
{
    keccak((const uint8_t*) a_in, a_in_size, (uint8_t *) a_out,(int)  a_out_size );
}

static inline void dap_hash(const void * a_data_in, size_t a_data_in_size,
                     void * a_data_out, size_t a_data_out_size,
                     dap_hash_type_t a_type ){
    switch (a_type){
        case DAP_HASH_TYPE_KECCAK:
            dap_hash_keccak(a_data_in,a_data_in_size, a_data_out,a_data_out_size);
        break;
//        case DAP_HASH_TYPE_SLOW_0:
//            if( a_data_out_size>= dap_hash_slow_size() ){
//                dap_hash_slow(a_data_in,a_data_in_size,(char*) a_data_out);
//            }
//        break;
    }
}

int dap_hash_fast( const void *a_data_in, size_t a_data_in_size, dap_chain_hash_fast_t *a_hash_out )
{
    if(!a_data_in || !a_data_in_size || !a_hash_out)
        return -1;

    dap_hash( a_data_in, a_data_in_size, a_hash_out->raw, sizeof(a_hash_out->raw),
            DAP_HASH_TYPE_KECCAK);

    return 1;
}
*/
#define DATA_SIZE 2048

uint8_t data[8192];
uint8_t data2[8192];

Keccak_HashInstance ki0;

#define print_hash( x )          \
  printf( "  hash = " );         \
  for( int g = 0; g < 32; ++g )  \
    printf( "%02X", x[g] );      \
  printf( "\n" );                \

void dap_sha3_tests_run(void)
{
  dap_chain_hash_fast_t hash0;
  uint64_t start;
  double t;

  uint8_t hash2[32];

  dap_print_module_name("dap_sha3_tests_run( )");

//  printf("dap_hash_fast( ) of %u data x %u ...\n", DATA_SIZE, 65536 );

  for (int i = 0; i < DATA_SIZE; ++ i ) {
    data[i] = zRAND( ) & 255;
  }

  zRAND_reset( );
  start = gettime64( );

  for (int h = 0; h < 65536; h ++ ) {
    dap_hash_fast( &data[0], DATA_SIZE, &hash0 );
  }

  t = (double)(gettime64( ) - start) / 1000000000.0;
  benchmark_mgs_rate( "dap_hash_fast_sha3(monero_crypto)(2048)", 65536.0 / t );
  print_hash( hash0.raw );

//  printf("Keccak_sha_256( ) of %u data x %u ...\n", DATA_SIZE,  65536 );
  start = gettime64( );

  for (int h = 0; h < 65536; h ++ ) {
    SHA3_256( &hash2[0], &data[0], DATA_SIZE );
  }
  t = (double)(gettime64( ) - start) / 1000000000.0;
  benchmark_mgs_rate( "SHA_256(XKCP)(2048)", 65536.0 / t );
  print_hash( hash2 );

//  printf("sha3_512(dap_crypto) of %u data x %u ...\n", DATA_SIZE,  65536 );
  start = gettime64( );

  for (int h = 0; h < 65536; h ++ ) {
      sha3_256( &hash2[0], &data[0], DATA_SIZE );
  }

  t = (double)(gettime64( ) - start) / 1000000000.0;
  benchmark_mgs_rate( "sha3_256(dap_crypto)(2048)", 65536.0 / t );

  print_hash( hash2 );

//  printf("shake256(dap_crypto) of %u data x %u ...\n", DATA_SIZE,  65536 );
  start = gettime64( );

  for (int h = 0; h < 65536; h ++ ) {
      shake256( &hash2[0], 32, &data[0], DATA_SIZE );
  }

  t = (double)(gettime64( ) - start) / 1000000000.0;
  benchmark_mgs_rate( "shake256(dap_crypto)(2048)", 65536.0 / t );
  print_hash( hash2 );

//  printf("SHAKE256 of %u data x %u ...\n", DATA_SIZE,  65536 );
  start = gettime64( );

  for (int h = 0; h < 65536; h ++ ) {
      SHAKE256( &hash2[0], 32, &data[0], DATA_SIZE );
  }

  t = (double)(gettime64( ) - start) / 1000000000.0;
  benchmark_mgs_rate( "SHAKE256(XKCP)(2048)", 65536.0 / t );

  print_hash( hash2 );

  dap_pass_msg("dap_sha3_tests_run( )");

  return;
}
