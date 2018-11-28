#include <math.h>
#include <stdio.h>
#include <stdint.h>
#include <ctype.h>
#include <stdlib.h>
#include <string.h>

#include "dap_enc_base64.h"

typedef unsigned char byte;

// get the size of the result buffer required for Base-64
// encoding/decoding.
// sz - size of original buffer to be encoded/decoded
// isEncoded - true (1) when encoding the original buffer;
//				false (0) when decoding the original buffer.
int B64_GetSize( int sz, int isEncode );

// Base-64 encode the given byte array
// outChars - buffer of length returned by GetSize(), filled upon return
void B64_Encode( const byte* srcBytes, int srcLen, char* outChars );

// Base-64 decode the given string
// srcChars - characters to be decoded
// outBytes - buffer of length returned by GetSize(), filled upon return
void B64_Decode( const char* srcChars, int srcLen, byte* outBytes );

// return the Base-64 encoded char for the given source byte
char B64_EncodeByte( byte b );

// return the Base-64 decoded byte for the given source char
// <returns></returns>
byte B64_DecodeByte( byte b );

#ifndef b64_malloc
#  define b64_malloc(ptr) malloc(ptr)
#endif
#ifndef b64_realloc
#  define b64_realloc(ptr, size) realloc(ptr, size)
#endif

/**
 * @breif Base64 index table.
 */

static const char b64_standart_table[] = {
    'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H',
    'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P',
    'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X',
    'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f',
    'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n',
    'o', 'p', 'q', 'r', 's', 't', 'u', 'v',
    'w', 'x', 'y', 'z', '0', '1', '2', '3',
    '4', '5', '6', '7', '8', '9', '+', '/'
};

/**
 * @breif Base64 url safe index table.
 */
static const char b64_table_url_safe[] = {
    'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H',
    'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P',
    'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X',
    'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f',
    'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n',
    'o', 'p', 'q', 'r', 's', 't', 'u', 'v',
    'w', 'x', 'y', 'z', '0', '1', '2', '3',
    '4', '5', '6', '7', '8', '9', '-', '_'
};

/**
 * Encode `unsigned char *' source with `size_t' size.
 * Returns a `char *' base64 encoded string.
 */

char *
b64_encode (const unsigned char *, size_t);

/**
 * Dencode `char *' source with `size_t' size.
 * Returns a `unsigned char *' base64 decoded string.
 */
unsigned char *
b64_decode (const char *, size_t);

/**
 * Dencode `char *' source with `size_t' size.
 * Returns a `unsigned char *' base64 decoded string + size of decoded string.
 */
unsigned char *
b64_decode_ex (const char *, size_t, size_t *);

/**
 * @brief b64_table_by_standard The function returns the corresponding table of indices
 * @param[in] standard Base64 or Base64 URLSAFE encoding
 * @return index table
 */
static const char* b64_table_by_standard(dap_enc_data_type_t standard)
{
    switch (standard) {
    case DAP_ENC_DATA_TYPE_B64:
        return b64_standart_table;
    case DAP_ENC_DATA_TYPE_B64_URLSAFE:
        return b64_table_url_safe;
    default:
        perror("Unknown base64 standard");
        abort();
    }
}

/**
 * @brief dap_enc_base64_decode Function of reverse transformation of base64 algorithm
 * @param[in] in Pointer to an array with incoming data
 * @param[in] in_size Size of the array with outgoing data
 * @param[out] out Pointer to an array with outgoing data
 * @return Size of the array with outgoing data
 */
size_t dap_enc_base64_decode(const char * in, size_t in_size,void * out, dap_enc_data_type_t standard)
{
    uint8_t * out_bytes = (uint8_t*) out;

    int j = 0;
    int8_t l = 0, i = 0;
    size_t l_size = 0;
    unsigned char buf[3];
    unsigned char tmp[4];

    const char* b64_table = b64_table_by_standard(standard);

    if (NULL == out) { return 0; }

    // parse until end of source
    while (in_size--) {
        // break if char is `=' or not base64 char
        if ('=' == in[j]) { break; }

        if (!(isalnum(in[j]) || in[j] == b64_table[62] || in[j] == b64_table[63]))
            break;

        // read up to 4 bytes at a time into `tmp'
        tmp[i++] = in[j++];

        // if 4 bytes read then decode into `buf'
        if (4 == i) {
            // translate values in `tmp' from table
            for (i = 0; i < 4; ++i) {
                // find translation char in `b64_table'
                for (l = 0; l < 64; ++l) {
                    if (tmp[i] == b64_table[l]) {
                        tmp[i] = l;
                        break;
                    }
                }
            }

            // decode
            buf[0] = (tmp[0] << 2) + ((tmp[1] & 0x30) >> 4);
            buf[1] = ((tmp[1] & 0xf) << 4) + ((tmp[2] & 0x3c) >> 2);
            buf[2] = ((tmp[2] & 0x3) << 6) + tmp[3];

            // write decoded buffer to `dec'
            for (i = 0; i < 3; ++i) {
                out_bytes[l_size++] = buf[i];
            }

            // reset
            i = 0;
        }
    }

    // remainder
    if (i > 0) {
        // fill `tmp' with `\0' at most 4 times
        for (j = i; j < 4; ++j) {
            tmp[j] = '\0';
        }

        // translate remainder
        for (j = 0; j < 4; ++j) {
            // find translation char in `b64_table'
            for (l = 0; l < 64; ++l) {
                if (tmp[j] == b64_table[l]) {
                    tmp[j] = l;
                    break;
                }
            }
        }

        // decode remainder
        buf[0] = (tmp[0] << 2) + ((tmp[1] & 0x30) >> 4);
        buf[1] = ((tmp[1] & 0xf) << 4) + ((tmp[2] & 0x3c) >> 2);
        buf[2] = ((tmp[2] & 0x3) << 6) + tmp[3];

        // write remainer decoded buffer to `dec'
        for (j = 0; (j < i - 1); ++j) {
            out_bytes[l_size++] = buf[j];
        }

    }

    return l_size;
}

/**
 * @brief dap_enc_base64_encode The function encodes the array according to the base64 algorithm
 * @param[in] a_in Array with incoming data
 * @param[in] a_in_size The size of the deviance array in the a_in parameter
 * @param[out] a_out A pointer to an array in which the data will be after encoding
 * @return Size of the array with outgoing data
 */
size_t dap_enc_base64_encode(const void * a_in, size_t a_in_size, char * a_out, dap_enc_data_type_t standard)
{
    uint8_t i = 0;
    int j = 0;
    size_t size = 0;
    unsigned char buf[4];
    unsigned char tmp[3];
    const unsigned char * l_in_bytes = (const unsigned char*) a_in;

    const char* b64_table = b64_table_by_standard(standard);

    if (NULL == a_out) { return 0; }

    // parse until end of source
    while (a_in_size--) {
        // read up to 3 bytes at a time into `tmp'
        tmp[i++] = *(  l_in_bytes++);

        // if 3 bytes read then encode into `buf'
        if (3 == i) {
            buf[0] = (tmp[0] & 0xfc) >> 2;
            buf[1] = ((tmp[0] & 0x03) << 4) + ((tmp[1] & 0xf0) >> 4);
            buf[2] = ((tmp[1] & 0x0f) << 2) + ((tmp[2] & 0xc0) >> 6);
            buf[3] = tmp[2] & 0x3f;

            for (i = 0; i < 4; ++i) {
                a_out[size++] = b64_table[buf[i]];
            }

            // reset index
            i = 0;
        }
    }

    // remainder
    if (i > 0) {
        // fill `tmp' with `\0' at most 3 times
        for (j = i; j < 3; ++j) {
            tmp[j] = '\0';
        }

        // perform same codec as above
        buf[0] = (tmp[0] & 0xfc) >> 2;
        buf[1] = ((tmp[0] & 0x03) << 4) + ((tmp[1] & 0xf0) >> 4);
        buf[2] = ((tmp[1] & 0x0f) << 2) + ((tmp[2] & 0xc0) >> 6);
        buf[3] = tmp[2] & 0x3f;

        // perform same write to `enc` with new allocation
        for (j = 0; (j < i + 1); ++j) {
            a_out[size++] = b64_table[buf[j]];
        }

        // while there is still a remainder
        // append `=' to `enc'
        while ((i++ < 3)) {
            a_out[size++] = '=';
        }
    }
    return size;
}


// get the size of the result buffer required for Base-64
// encoding/decoding.
// sz - size of original buffer to be encoded/decoded
// isEncoded - true (1) when encoding the original buffer;
//				false (0) when decoding the original buffer.
int B64_GetSize( int sz, int isEncode )
{
    int n = 0;

    if( isEncode ) {
        n = ceil ( ((double) sz) / 3.0 ) * 4.0;
        switch( sz % 3 ) {
        case 0: break;
        case 1: n += 2; break;
        case 2: n += 3; break;
        }
    }
    else {
        n = ceil ( ((double) sz) / 4.0 ) * 3.0;
        switch( sz % 4 ) {
        case 0: break;
        case 1: break;
        case 2: n += 1; break;
        case 3: n += 2; break;
        }
    }
    return n;
}


// Base-64 encode the given byte array
// outChars - buffer of length returned by GetSize(), filled upon return
void B64_Encode( const byte* srcBytes, int srcLen, char* outChars )
{
    byte b1, b2, b3;
    byte* destBytes = (byte*)outChars;

    // walk through the source, taking 3 bytes at a time
    int srcNdx = 0;
    int destNdx = 0;
    int remaining = srcLen;
    for( ; remaining > 2; remaining -= 3 ) {
        b1 = srcBytes[ srcNdx++ ];
        b2 = srcBytes[ srcNdx++ ];
        b3 = srcBytes[ srcNdx++ ];
        destBytes[destNdx++] = B64_EncodeByte( (byte)( b1 >> 2 ) );
        destBytes[destNdx++] = B64_EncodeByte( (byte)( ( b1 << 4 ) | ( b2 >> 4 ) ) );
        destBytes[destNdx++] = B64_EncodeByte( (byte)( ( b2 << 2 ) | ( b3 >> 6 ) ) );
        destBytes[destNdx++] = B64_EncodeByte( (byte)b3 );
    }

    // process the remaining bytes
    b2 = 0;
    if( remaining > 0 ) {
        b1 = srcBytes[srcNdx++];
        if( remaining == 2 )
            b2 = srcBytes[srcNdx++];

        destBytes[destNdx++] = B64_EncodeByte( (byte)( b1 >> 2 ) );
        destBytes[destNdx++] = B64_EncodeByte( (byte)( ( b1 << 4 ) | ( b2 >> 4 ) ) );
        if( remaining == 2 )
            destBytes[destNdx++] = B64_EncodeByte( (byte)( b2 << 2 ) );
    }
}


// Base-64 decode the given string
// srcChars - characters to be decoded
// outBytes - buffer of length returned by GetSize(), filled upon return
void B64_Decode( const char* srcChars, int srcLen, byte* outBytes )
{
    byte b1, b2, b3, b4;
    const byte* srcBytes = (byte*)srcChars;
    byte* destBytes = outBytes;

    // walk through the source, taking 4 bytes at a time
    int srcNdx = 0;
    int destNdx = 0;
    int remaining = srcLen;
    for( ; remaining > 3; remaining -= 4 ) {
        b1 = B64_DecodeByte( srcBytes[srcNdx++] );
        b2 = B64_DecodeByte( srcBytes[srcNdx++] );
        b3 = B64_DecodeByte( srcBytes[srcNdx++] );
        b4 = B64_DecodeByte( srcBytes[srcNdx++] );

        destBytes[destNdx++] = (byte)( ( b1 << 2 ) | ( b2 >> 4 ) );
        destBytes[destNdx++] = (byte)( ( b2 << 4 ) | ( b3 >> 2 ) );
        destBytes[destNdx++] = (byte)( ( b3 << 6 ) | b4 );
    }

    // process the remaining bytes
    b2 = b3 = 0;
    if( remaining > 0 ) {
        b1 = B64_DecodeByte( srcBytes[srcNdx++] );
        if( remaining > 1 )
            b2 = B64_DecodeByte( srcBytes[srcNdx++] );
        if( remaining == 3 )
            b3 = B64_DecodeByte( srcBytes[srcNdx++] );

        destBytes[destNdx++] = (byte)( ( b1 << 2 ) | ( b2 >> 4 ) );
        if( remaining == 3 )
            destBytes[destNdx++] = (byte)( ( b2 << 4 ) | ( b3 >> 2 ) );
    }
}


// return the Base-64 encoded char for the given source byte
char B64_EncodeByte( byte b )
{
    b &= 0x3f;
    if( b <= 25 )
        return (byte)( b +'A' );
    if( b <= 51 )
        return (byte)( b - 26 + 'a' );
    if( b <= 61 )
        return (byte)( b - 52 + '0' );
    if( b == 62 )
        return (byte)'-';

    return (byte)'_';
}


// return the Base-64 decoded byte for the given source char
// <returns></returns>
byte B64_DecodeByte( byte b )
{
    if (( b == '+' ) || (b =='-') )
        return 62;
    if( (b == '/' ) || (b == '_') )
        return 63;
    if( b <= '9' )
        return (byte)( b - '0' + 52 );
    if( b <= 'Z' )
        return (byte)( b - 'A' );
    return (byte)( b - 'a' + 26 );
}

