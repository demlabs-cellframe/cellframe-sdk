#ifndef sodium_utils_H
#define sodium_utils_H

#include <stddef.h>


#define SODIUM_MIN(A, B) ((A) < (B) ? (A) : (B))
#define SODIUM_SIZE_MAX SODIUM_MIN(UINT64_MAX, SIZE_MAX)
#endif
