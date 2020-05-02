#include <assert.h>
#include <string.h>
#include "tesla_params.h"


static const tesla_param_t tesla_params[] = {

  { qTESLA_I,          /* kind */
    512,
    9,
    23.78,
    27.9988,
    4205569,
    23,
    3098553343,
    1021,
    32,
    1048575,
    20,
    1,
    23.78,
    30,
    21,
    19,
    1586,
    1586,
    1586,
    1586,
    113307,

    1376,//((512*21+7)/8 + 32),
    2112,//2*sizeof(int16_t)*512 + 2*32,
    1504 //((512*23+7)/8 + 32)
  },

  { qTESLA_III_size,   /* kind */
    1024,
    10,
    8.49,
    9.9962,
    4206593,
    23,
    4148178943,
    1021,
    32,
    1048575,
    20,
    1,
    8.49,
    48,
    21,
    38,
    910,
    910,
    910,
    910,
    1217638,

    2720,//((PARAM_N*PARAM_D+7)/8 + CRYPTO_C_BYTES)
    4160,//(2*sizeof(int16_t)*PARAM_N + 2*CRYPTO_SEEDBYTES)
    2976 //((PARAM_N*PARAM_Q_LOG+7)/8 + CRYPTO_SEEDBYTES)
  },

  { qTESLA_III_speed,  /* kind */
    1024,
    10,
    10.2,
    12,
    8404993,
    24,
    4034936831,
    511,
    32,
    2097151,
    21,
    1,
    10.2,
    48,
    22,
    38,
    1147,
    1147,
    1233,
    1233,
    237839,

    2848,//((PARAM_N*PARAM_D+7)/8 + CRYPTO_C_BYTES)
    4160,//(2*sizeof(int16_t)*PARAM_N + 2*CRYPTO_SEEDBYTES)
    3104 //((PARAM_N*PARAM_Q_LOG+7)/8 + CRYPTO_SEEDBYTES)
  },

  { qTESLA_p_I,        /* kind */
    1024,
    10,
    8.5,
    10,
    485978113,
    29,
    3421990911,
    1,
    29,
    2097151,
    21,
    4,
    8.5,
    25,
    22,
    108,
    554,
    554,
    554,
    554,
    472064468,

    2848,//((PARAM_N*PARAM_D+7)/8 + CRYPTO_C_BYTES)
    5184,//(sizeof(int8_t)*PARAM_N + sizeof(int8_t)*PARAM_N*PARAM_K + 2*CRYPTO_SEEDBYTES)
    14880 //((PARAM_Q_LOG*PARAM_N*PARAM_K+7)/8 + CRYPTO_SEEDBYTES)
  },

  { qTESLA_p_III,      /* kind */
    2048,
    11,
    8.5,
    10,
    1129725953,
    31,
    861290495,
    15,
    34,
    8388607,
    23,
    5,
    8.5,
    40,
    24,
    180,
    901,
    901,
    901,
    901,
    851423148,

    6176,//((PARAM_N*PARAM_D+7)/8 + CRYPTO_C_BYTES)
    12352,//(sizeof(int8_t)*PARAM_N + sizeof(int8_t)*PARAM_N*PARAM_K + 2*CRYPTO_SEEDBYTES)
    39712 //((PARAM_Q_LOG*PARAM_N*PARAM_K+7)/8 + CRYPTO_SEEDBYTES)
  },
};

bool tesla_params_init(tesla_param_t *params, tesla_kind_t kind){
  assert(params != NULL);

  memset(params, 0, sizeof(tesla_param_t));
  
  if (qTESLA_I <= kind && kind <= qTESLA_p_III  && params != NULL) {
    *params = tesla_params[kind];
    return true;
  } else {
    return false;
  }
}
