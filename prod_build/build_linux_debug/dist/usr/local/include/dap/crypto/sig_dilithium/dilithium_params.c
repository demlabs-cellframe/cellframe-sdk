#include <assert.h>
#include <string.h>
#include "dilithium_params.h"


static const dilithium_param_t dilithium_params[] = {

  { MODE_0,          /* kind */
    3,
    2,
    7,
    4,
    375,
    64,
    736,
    288,
    448,
    128,
    640,
    128,
    2208,
    1472,

    896,
    2096,
    1387
  },

  { MODE_1,   /* kind */
    4,
    3,
    6,
    4,
    325,
    80,
    736,
    288,
    448,
    128,
    640,
    128,
    2944,
    2208,

    1184,
    2800,
    2044

  },

  { MODE_2,  /* kind */
    5,
    4,
    5,
    4,
    275,
    96,
    736,
    288,
    448,
    128,
    640,
    128,
    3680,
    2944,

    1472,
    3504,
    2701
  },

  { MODE_3,        /* kind */
    6,
    5,
    3,
    3,
    175,
    120,
    736,
    288,
    448,
    96,
    640,
    128,
    4416,
    3680,

    1760,
    3856,
    3366
  },  
};

bool dilithium_params_init(dilithium_param_t *params, dilithium_kind_t kind){
  if(!params)
      return false;

  memset(params, 0, sizeof(dilithium_param_t));
  
  if (MODE_0 <= kind && kind <= MODE_3  && params != NULL) {
    *params = dilithium_params[kind];
    return true;
  } else {
    return false;
  }
}
