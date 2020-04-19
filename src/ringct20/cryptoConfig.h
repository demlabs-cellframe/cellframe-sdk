#ifndef _CRYPTOCONFIG_H
#define _CRYPTOCONFIG_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/******************************************************************************/
typedef unsigned __int64	uint64;
typedef unsigned long		uint32;
typedef unsigned char		uint8;

//rotate left(circular left shift) operation
#define ROTL(value, bits)	(((value) << (bits)) | ((value) >> (32-bits)))
//rotate right(circular right shift) operation
#define ROTR(value, bits)	(((value) >> (bits)) | ((value) << (32-bits)))
//right left operation
#define SHL(value, bits)	((value) << (bits))
//right shift operation
#define SHR(value, bits)	((value) >> (bits))

#define MAX(a, b) ((a) > (b)) ? (a) : (b)
#define MIN(a, b) ((a) < (b)) ? (a) : (b)

/******************************************************************************/


#define USE_SHA256


#endif/* _CRYPTOCONFIG_H */