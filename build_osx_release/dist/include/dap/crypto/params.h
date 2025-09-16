#define str(s) #s
#define xstr(s) str(s)

#ifdef SPHINCSPLUS_FLEX
#include "sphincsplus_global.h"
#else
#include xstr(params/params-PARAMS.h)
#endif

