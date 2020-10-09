#include <unistd.h>
#include "dap_common.h"
#include "dap_enc_test.h"
#include "dap_test.h"
#include "rand/dap_rand.h"
#include "dap_enc_key.h"
#include "dap_enc_base64.h"
#include "dap_enc_bliss.h"
#include "dap_enc_picnic.h"
#include "dap_enc_tesla.h"
#include "dap_enc_dilithium.h"
#include "dap_enc.h"
#include "dap_test.h"

#define TEST_SER_FILE_NAME "keystorage.txt"
void test_encypt_decrypt(int count_steps, const dap_enc_key_type_t key_type, const int cipher_key_size)
{
    dap_print_module_name(dap_enc_get_type_name(key_type));
    const int max_source_size = 10000;
    int time_beg = get_cur_time_msec();



    for(int i = 0; i < count_steps; i++) {
        size_t source_size = 0;
        const size_t seed_size = 16;
        uint8_t seed[seed_size];

        const size_t kex_size = 32;
        uint8_t kex[kex_size];
        randombytes(seed, seed_size);
        randombytes(kex, kex_size);

        dap_enc_key_t* key = dap_enc_key_new_generate(key_type, kex, kex_size, seed, seed_size, cipher_key_size);
        source_size = 256;//1 + random_uint32_t(max_source_size);

        uint8_t *source = DAP_NEW_SIZE(uint8_t, source_size);

        randombytes(source, source_size);//randombase64(source, source_size);
        uint8_t * buf_encrypted = NULL;
        uint8_t * buf_decrypted = NULL;


        size_t encrypted_size = key->enc(key, source, source_size, (void**) &buf_encrypted);
        size_t result_size = key->dec(key, buf_encrypted, encrypted_size, (void**) &buf_decrypted);

        dap_assert_PIF(source_size == result_size, "Check result decode size");

        dap_assert_PIF(memcmp(source, buf_decrypted, source_size) == 0,
                "Check source and encode->decode data");

        DAP_DELETE(source);
        DAP_DELETE(buf_encrypted);
        DAP_DELETE(buf_decrypted);
        dap_enc_key_delete(key);
    }
    int time_end = get_cur_time_msec();
    char pass_msg_buf[256];
    snprintf(pass_msg_buf, sizeof(pass_msg_buf), "Encode and decode      %d times T = %f (%f per once)", count_steps, (time_end - time_beg)/1000.0,(time_end - time_beg)/1000.0/count_steps);
    dap_pass_msg(pass_msg_buf);

}

void test_encypt_decrypt_fast(int count_steps, const dap_enc_key_type_t key_type, const int cipher_key_size)
{
    const int max_source_size = 10000;
    dap_print_module_name(dap_enc_get_type_name(key_type));
    char buf_encrypt_out[max_source_size+128];
    char buf_decrypt_out[max_source_size+32];
    int time_beg = get_cur_time_msec();


    size_t seed_size = 16;
    uint8_t seed[seed_size];

    size_t kex_size = 32;
    uint8_t kex[kex_size];

    randombytes(seed, seed_size);
    randombytes(kex, kex_size);

    dap_enc_key_t* key = dap_enc_key_new_generate(key_type, kex, kex_size, seed, seed_size, cipher_key_size);

    size_t source_size = 0;

    for(int i = 0; i < count_steps; i++) {
        source_size = 1 + random_uint32_t(max_source_size);
//        printf("ss = %d\n", source_size);fflush(stdout);

        uint8_t *source = DAP_NEW_SIZE(uint8_t,source_size + 0);
        randombytes(source, source_size);//randombase64(source, source_size);


        size_t encrypted_size = key->enc_na(key, source, source_size, buf_encrypt_out, max_source_size+128);

        size_t result_size = key->dec_na(key, buf_encrypt_out, encrypted_size, buf_decrypt_out, max_source_size+32);



        dap_assert_PIF(source_size == result_size, "Check result decode size");

        dap_assert_PIF(memcmp(source, buf_decrypt_out, source_size) == 0,
                "Check source and encode->decode data");
        DAP_DELETE(source);
    }

    dap_enc_key_delete(key);
    int time_end = get_cur_time_msec();
    char pass_msg_buf[256];
    snprintf(pass_msg_buf, sizeof(pass_msg_buf), "Encode and decode fast %d times T = %f (%f per once)", count_steps, (time_end - time_beg)/1000.0,(time_end - time_beg)/1000.0/count_steps);
    dap_pass_msg(pass_msg_buf);
}


static void _encrypt_decrypt(enum dap_enc_key_type key_type,
                             enum dap_enc_data_type data_type,
                             size_t count_steps)
{
    size_t source_size = 1;
    const int MAX_SEED_SIZE = 100;
    uint8_t seed[MAX_SEED_SIZE];
    for (size_t i = 0; i < count_steps; i++) {
        source_size = 1 + random_uint32_t(2000);

        const char *kex_data = "123";
        size_t kex_size = strlen(kex_data);
        const size_t seed_size = 1 + random_uint32_t(MAX_SEED_SIZE-1);

        randombytes(seed, seed_size);
//        printf("i = %d ss = %d, ss=%d\n",i, source_size,seed_size );fflush(stdout);
        uint8_t *source = DAP_NEW_SIZE(uint8_t, source_size);
//        printf(".");fflush(stdout);
        randombytes(source, source_size);
//        printf(".");fflush(stdout);
        dap_enc_key_t* key = dap_enc_key_new_generate(key_type, kex_data, kex_size, seed, seed_size, 0);
//        printf(".");fflush(stdout);

        size_t encrypt_buff_size = dap_enc_code_out_size(key, source_size, data_type);
        uint8_t *encrypt_result = DAP_NEW_SIZE(uint8_t, encrypt_buff_size);
//        printf(".");fflush(stdout);
        size_t encrypted_size = dap_enc_code(key, source,
                                             source_size,
                                             encrypt_result,
                                             encrypt_buff_size,
                                             data_type);
//        printf(".");fflush(stdout);
        size_t min_decode_buff_size = dap_enc_decode_out_size(key, encrypt_buff_size, data_type);
//        printf(".");fflush(stdout);
        uint8_t *decode_result = DAP_NEW_SIZE(uint8_t, min_decode_buff_size);
//        printf(".");fflush(stdout);
        size_t out_size = dap_enc_decode(key,
                                         encrypt_result,
                                         encrypted_size,
                                         decode_result,
                                         min_decode_buff_size,
                                         data_type);
//        printf("source_size = %d, out_size = %d, min_decode_buff_size = %d, encrypt_buff_size = %d, encrypted_size = %d\n",
//               source_size, out_size,min_decode_buff_size, encrypt_buff_size, encrypted_size);
//        printf("%.2x%.2x\n", source[0], source[1]);
//        printf(".");fflush(stdout);

        dap_assert_PIF(source_size == out_size, "Check result decode size");

//        printf(".");fflush(stdout);
        dap_assert_PIF(memcmp(source, decode_result, source_size) == 0, "Check source and encode->decode data");
//        printf(".");fflush(stdout);
//#ifdef xxxxx



//#endif
        DAP_DELETE(decode_result);
        DAP_DELETE(encrypt_result);
        DAP_DELETE(source);
        dap_enc_key_delete(key);
    }
}

void test_encode_decode_raw(size_t count_steps)
{
    _encrypt_decrypt(DAP_ENC_KEY_TYPE_IAES, DAP_ENC_DATA_TYPE_RAW, count_steps);
    dap_pass_msg("Encode->decode raw");
}

void test_encode_decode_raw_b64(size_t count_steps)
{
    _encrypt_decrypt(DAP_ENC_KEY_TYPE_IAES, DAP_ENC_DATA_TYPE_B64, count_steps);
    dap_pass_msg("Encode->decode raw base64");
}

void test_encode_decode_raw_b64_url_safe(size_t count_steps)
{
    _encrypt_decrypt(DAP_ENC_KEY_TYPE_IAES, DAP_ENC_DATA_TYPE_B64_URLSAFE, count_steps);
    dap_pass_msg("Encode->decode raw base64 url safe");
}

void test_key_transfer_msrln()
{
    uint8_t *alice_msg;
    size_t alice_msg_len;

    uint8_t *bob_msg;
    size_t bob_msg_len;

    dap_enc_key_t* alice_key = dap_enc_key_new_generate(DAP_ENC_KEY_TYPE_MSRLN, NULL, 0, NULL, 0, 0);

    // generate Alice msg
    alice_msg = alice_key->pub_key_data;
    alice_msg_len = alice_key->pub_key_data_size;

    /* generate Bob's response */
    dap_enc_key_t* bob_key = dap_enc_key_new(DAP_ENC_KEY_TYPE_MSRLN);
    bob_key->gen_bob_shared_key(bob_key, (unsigned char *) alice_msg, alice_msg_len,
                                (void **) &bob_key->pub_key_data);
    bob_msg = bob_key->pub_key_data;
    bob_msg_len = bob_key->pub_key_data_size;

    /* Alice processes Bob's response */
    bob_key->gen_alice_shared_key(alice_key, alice_key->priv_key_data, bob_msg_len, (unsigned char*)bob_msg);

    /* compare session key values */
    dap_assert(memcmp(alice_key->priv_key_data, bob_key->priv_key_data, alice_key->priv_key_data_size) == 0, "Session keys equals");

    dap_enc_key_delete(alice_key);
    dap_enc_key_delete(bob_key);

    dap_pass_msg("Key transfer simulation");
}

static void init_test_case()
{
    dap_enc_key_init();
}

static void cleanup_test_case()
{
    dap_enc_key_deinit();
}

static void _write_key_in_file(void* key, size_t key_size,
                               const char* file_name)
{
    FILE *f = fopen(file_name, "wb");
    dap_assert(f, "Create file");
    fwrite(key, key_size, 1, f);
    fclose(f);
}

void* _read_key_from_file(const char* file_name, size_t key_size)
{
    FILE *f = fopen(file_name, "rb");
    dap_assert(f, "Open key file");
    void* resut_key = calloc(1, key_size);//sizeof(dap_enc_key_serealize_t)
    fread(resut_key, key_size, 1, f);// sizeof(dap_enc_key_serealize_t)
    fclose(f);
    return resut_key;
}

/**
 * @key_type may be DAP_ENC_KEY_TYPE_IAES, DAP_ENC_KEY_TYPE_OAES
 */
static void test_serealize_deserealize(dap_enc_key_type_t key_type)
{
    const char *kex_data = "1234567890123456789012345678901234567890";//"123";
    size_t kex_size = strlen(kex_data);
    const size_t seed_size = 1 + random_uint32_t( 1000);
    uint8_t seed[seed_size];

    randombytes(seed, seed_size);

//  for key_type==DAP_ENC_KEY_TYPE_OAES must be: key_size=[16|24|32] and kex_size>=key_size
    dap_enc_key_t* key = dap_enc_key_new_generate(key_type, kex_data, kex_size, seed, seed_size, 32);
    dap_enc_key_serealize_t* serealize_key = dap_enc_key_serealize(key);
    _write_key_in_file(serealize_key, sizeof (dap_enc_key_serealize_t), TEST_SER_FILE_NAME);
    dap_enc_key_serealize_t* deserealize_key = _read_key_from_file(TEST_SER_FILE_NAME, sizeof(dap_enc_key_serealize_t));
    dap_assert(memcmp(serealize_key, deserealize_key, sizeof(dap_enc_key_serealize_t)) == 0,
               "dap_enc_key_serealize_t equals");

    dap_enc_key_t* key2 = dap_enc_key_deserealize(deserealize_key, sizeof (*deserealize_key));

    dap_assert(key->type == key2->type, "Key type");
    dap_assert(key->last_used_timestamp == key2->last_used_timestamp,
               "Last used timestamp");
    dap_assert(key->priv_key_data_size == key2->priv_key_data_size, "Priv key data size");
    dap_assert(key->pub_key_data_size == key2->pub_key_data_size, "Pub key data size");

    dap_assert(memcmp(key->priv_key_data, key2->priv_key_data, key2->priv_key_data_size) == 0,
               "Priv key data");

    if(key->pub_key_data_size) {
        dap_assert(memcmp(key->pub_key_data, key2->pub_key_data, key2->pub_key_data_size) == 0,
                   "Pub key data");
    }
    dap_assert(key->enc == key2->enc, "Enc callback");
    dap_assert(key->dec == key2->dec, "Dec callback");

    const char* source = "simple test";
    size_t source_size = strlen(source);

    size_t encrypt_size = dap_enc_code_out_size(key, source_size, DAP_ENC_DATA_TYPE_RAW);
    uint8_t encrypt_result[encrypt_size];


    size_t encrypted_size = dap_enc_code(key2, source,
                                         source_size,
                                         encrypt_result,
                                         encrypt_size,
                                         DAP_ENC_DATA_TYPE_RAW);

    size_t min_decode_size = dap_enc_decode_out_size(key, encrypt_size, DAP_ENC_DATA_TYPE_RAW);

    uint8_t decode_result[min_decode_size];
    size_t decode_size = dap_enc_decode(key,
                                        encrypt_result,
                                        encrypted_size,
                                        decode_result,
                                        min_decode_size,
                                        DAP_ENC_DATA_TYPE_RAW);

    dap_assert_PIF(source_size == decode_size, "Check result decode size");

    dap_assert_PIF(memcmp(source, decode_result, source_size) == 0,
                   "Check source and encode->decode data");

    free(serealize_key);
    free(deserealize_key);
    dap_enc_key_delete(key);
    dap_enc_key_delete(key2);

    dap_pass_msg("Key serealize->deserealize");
    unlink(TEST_SER_FILE_NAME);
}

/**
 * @key_type may be DAP_ENC_KEY_TYPE_SIG_BLISS, DAP_ENC_KEY_TYPE_SIG_TESLA, DAP_ENC_KEY_TYPE_SIG_PICNIC
 */
static void test_serealize_deserealize_pub_priv(dap_enc_key_type_t key_type)
{
    const char *kex_data = "1234567890123456789012345678901234567890"; //"123";
    size_t kex_size = strlen(kex_data);
    const size_t seed_size = 1 + random_uint32_t( 1000);
    uint8_t seed[seed_size];
    randombytes(seed, seed_size);

    // Generate key
    dap_enc_key_t* key = dap_enc_key_new_generate(key_type, kex_data, kex_size, seed, seed_size, 32);
    // Serialize key & save/read to/from buf
    size_t l_data_pub_size = 0;
    //uint8_t *l_data_pub = DAP_NEW_SIZE(uint8_t, l_data_pub_size);//dap_enc_key_serealize_pub_key(key, &l_data_pub_size);
    uint8_t *l_data_pub = dap_enc_key_serealize_pub_key(key, &l_data_pub_size);
    _write_key_in_file(l_data_pub, l_data_pub_size, TEST_SER_FILE_NAME);
    uint8_t *l_data_pub_read = _read_key_from_file(TEST_SER_FILE_NAME, l_data_pub_size);

    size_t l_data_priv_size = 0;
    uint8_t *l_data_priv = dap_enc_key_serealize_priv_key(key, &l_data_priv_size);
    _write_key_in_file(l_data_priv, l_data_priv_size, TEST_SER_FILE_NAME);
    uint8_t *l_data_priv_read = _read_key_from_file(TEST_SER_FILE_NAME, l_data_priv_size);

    // create new key2
    dap_enc_key_t *key2 = dap_enc_key_new(key_type);
    // Deserialize key2
    dap_enc_key_deserealize_pub_key(key2, l_data_pub_read, l_data_pub_size);
    dap_enc_key_deserealize_priv_key(key2, l_data_priv_read, l_data_priv_size);

    DAP_DELETE(l_data_pub);
    DAP_DELETE(l_data_pub_read);
    DAP_DELETE(l_data_priv);
    DAP_DELETE(l_data_priv_read);

    dap_assert(key->priv_key_data_size == key2->priv_key_data_size, "Priv key data size");
    dap_assert(key->pub_key_data_size == key2->pub_key_data_size, "Pub key data size");
    dap_pass_msg("Key serealize->deserealize");

    size_t source_size = 10 + random_uint32_t( 20);
    uint8_t source_buf[source_size];
    size_t sig_buf_size = 0;
    uint8_t *sig_buf = NULL;
    randombytes(source_buf, source_size);

    // encode by key
    int is_sig = 0, is_vefify = 0;
    switch (key_type) {
    case DAP_ENC_KEY_TYPE_SIG_BLISS:
        sig_buf_size = sizeof(bliss_signature_t);
        sig_buf = calloc(sig_buf_size, 1);
        if(dap_enc_sig_bliss_get_sign(key, source_buf, source_size, sig_buf, sig_buf_size) == BLISS_B_NO_ERROR)
            is_sig = 1;
        break;
    case DAP_ENC_KEY_TYPE_SIG_PICNIC:
        sig_buf_size = dap_enc_picnic_calc_signature_size(key);
        sig_buf = calloc(sig_buf_size, 1);
        if(key->enc_na(key, source_buf, source_size, sig_buf, sig_buf_size) > 0)
            is_sig = 1;
        break;
    case DAP_ENC_KEY_TYPE_SIG_TESLA:
        sig_buf_size = dap_enc_tesla_calc_signature_size();
        sig_buf = calloc(sig_buf_size, 1);
        if(key->enc_na(key, source_buf, source_size, sig_buf, sig_buf_size) > 0)
            is_sig = 1;
        break;
    case DAP_ENC_KEY_TYPE_SIG_DILITHIUM:
        sig_buf_size = dap_enc_dilithium_calc_signature_unserialized_size();
        sig_buf = calloc(sig_buf_size, 1);
        if(key->enc_na(key, source_buf, source_size, sig_buf, sig_buf_size) > 0)
            is_sig = 1;
        break;
    default:
        sig_buf_size = 0;
    }
    dap_enc_key_delete(key);

    dap_assert_PIF(sig_buf_size>0 && is_sig==1, "Check make signature");

    // serealize & deserealize signature
    size_t sig_buf_len = sig_buf_size;
    uint8_t *l_sign_tmp = dap_enc_key_serealize_sign(key_type, sig_buf, &sig_buf_len);
    dap_enc_key_signature_delete(key_type, sig_buf);
    sig_buf = dap_enc_key_deserealize_sign(key_type, l_sign_tmp, &sig_buf_len);
    DAP_DELETE(l_sign_tmp);

    dap_assert_PIF(sig_buf, "Check serealize->deserealize signature");

    // decode by key2
    switch (key_type) {
    case DAP_ENC_KEY_TYPE_SIG_BLISS:
        if(dap_enc_sig_bliss_verify_sign(key2, source_buf, source_size, sig_buf, sig_buf_size) == BLISS_B_NO_ERROR)
            is_vefify = 1;
        break;
    case DAP_ENC_KEY_TYPE_SIG_PICNIC:
        if(key2->dec_na(key2, source_buf, source_size, sig_buf, sig_buf_size) == 0)
            is_vefify = 1;
        break;
    case DAP_ENC_KEY_TYPE_SIG_TESLA:
        if(key2->dec_na(key2, source_buf, source_size, sig_buf, sig_buf_size) == 0)
            is_vefify = 1;
        break;
    case DAP_ENC_KEY_TYPE_SIG_DILITHIUM:
        if(key2->dec_na(key2, source_buf, source_size, sig_buf, sig_buf_size) == 0)
            is_vefify = 1;
        break;
    default:
        is_vefify = 0;
    }
    //dap_enc_key_delete(key);
    dap_enc_key_delete(key2);
    dap_enc_key_signature_delete(key_type, sig_buf);


    dap_assert_PIF(is_vefify==1, "Check verify signature");

    dap_pass_msg("Verify signature");
    unlink(TEST_SER_FILE_NAME);
}

void dap_enc_tests_run() {
    dap_print_module_name("dap_enc");
    init_test_case();
    test_encode_decode_raw(500);
    test_encode_decode_raw_b64(500);
    test_encode_decode_raw_b64_url_safe(500);
    test_key_transfer_msrln();
    dap_print_module_name("dap_enc serealize->deserealize IAES");
    test_serealize_deserealize(DAP_ENC_KEY_TYPE_IAES);
    dap_print_module_name("dap_enc serealize->deserealize OAES");
    test_serealize_deserealize(DAP_ENC_KEY_TYPE_OAES);

    dap_print_module_name("dap_enc_sig serealize->deserealize BLISS");
    test_serealize_deserealize_pub_priv(DAP_ENC_KEY_TYPE_SIG_BLISS);
    dap_print_module_name("dap_enc_sig serealize->deserealize PICNIC");
    test_serealize_deserealize_pub_priv(DAP_ENC_KEY_TYPE_SIG_PICNIC);
    dap_print_module_name("dap_enc_sig serealize->deserealize TESLA");
    test_serealize_deserealize_pub_priv(DAP_ENC_KEY_TYPE_SIG_TESLA);
    dap_print_module_name("dap_enc_sig serealize->deserealize DILITHIUM");
    test_serealize_deserealize_pub_priv(DAP_ENC_KEY_TYPE_SIG_DILITHIUM);
    cleanup_test_case();
}
