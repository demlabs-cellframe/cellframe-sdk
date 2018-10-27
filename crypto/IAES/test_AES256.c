//#include <stdint.h>
//#include <stdio.h>
//#include <stdlib.h>
//#include <dap_aes_proto.h>

//size_t dap_enc_aes256_cbc_ecrypt(dap_enc_key *key, void *ivec, const void * a_in, size_t a_in_size, void ** a_out)
//{
//    int length_data_new;
//    uint8_t *data_new;

//    length_data_new = Block128_Padding(a_in, &data_new, a_in_size);
//    uint8_t *cdata = (uint8_t *)malloc(length_data_new);
//    if(0)
//        AES256_NI_CBC_encrypt(data_new, cdata, ivec, length_data_new, key);
//    else
//        AES256_CBC_encrypT(data_new, cdata, ivec, length_data_new, key);

//    * a_out = (uint8_t *) malloc(length_data_new);
//    memcpy(* a_out, cdata,(length_data_new));

//    free(cdata);
//    return length_data_new;
//  }

//size_t dap_enc_aes256_cbc_decrypt(dap_enc_key* key, void *ivec, const void * a_in, size_t a_in_size, void ** a_out)
//{
//    if (a_in_size % 16)
//        return 0;

//    uint8_t *data = (uint8_t *)malloc(a_in_size);
//    if(0)
//        AES256_NI_CBC_decrypt(a_in, data, ivec, a_in_size, key);
//    else
//        AES256_CBC_decrypT(a_in, data, ivec, a_in_size, key);

//    int padding = 0;
//    size_t end = a_in_size-16 > 0 ? a_in_size-16 : 0;
//    size_t i;
//    for( i = a_in_size-1; i >= end; i--)
//    {
//        if(*(char*)(data + i) == (char)0)
//            padding++;
//        else
//            break;
//    }

//    * a_out = (uint8_t *) malloc(a_in_size);
//    memcpy(* a_out, data,(a_in_size));
//    free(data);

//    return a_in_size - padding;
//  }

//int main()
//{
//    uint8_t a_in[10] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee,0xff};
//    uint8_t masterkey[32] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
//                             0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f};
//    uint8_t ivec[16] = {0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f};
//    uint8_t * a_out_enc;
//    uint8_t * a_out_dec;

//    size_t test1, test2;
//    size_t a_in_size = sizeof(a_in);
//    test1 = dap_enc_aes256_cbc_ecrypt(masterkey, ivec, a_in, a_in_size, &a_out_enc);


//    test2 = dap_enc_aes256_cbc_decrypt(masterkey, ivec, a_out_enc, test1, &a_out_dec);

//    if (memcmp(a_in, a_out_dec, test2)==0)
//        printf("SUCCESS");

//     return 0;
//}


