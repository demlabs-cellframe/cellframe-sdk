#include "dap_enc_test.h"
#include "dap_test.h"
#include "dap_test_generator.h"
#include "dap_enc_key.h"
#include "dap_enc_base64.h"
#include "dap_enc.h"

#define TEST_SER_FILE_NAME "keystorage.txt"

static void _encrypt_decrypt(enum dap_enc_key_type key_type,
                             enum dap_enc_data_type data_type,
                             size_t count_steps)
{
    size_t source_size = 1;

    for (size_t i = 0; i < count_steps; i++) {
        int step = 1 + (rand() % 20);
        source_size += (size_t)step;

        const char *kex_data = "123";
        size_t kex_size = strlen(kex_data);
        const size_t seed_size = 1 + (rand() % 1000);
        uint8_t seed[seed_size];

        generate_random_byte_array(seed, seed_size);

        dap_enc_key_t* key = dap_enc_key_new_generate(key_type, kex_data, kex_size, seed, seed_size, 0);


        uint8_t source[source_size];
        size_t encrypt_buff_size = dap_enc_code_out_size(key, source_size, data_type);
        uint8_t encrypt_result[encrypt_buff_size];

        generate_random_byte_array(source, source_size);

        size_t encrypted_size = dap_enc_code(key, source,
                                             source_size,
                                             encrypt_result,
                                             encrypt_buff_size,
                                             data_type);

        size_t min_decode_buff_size = dap_enc_decode_out_size(key, encrypt_buff_size, data_type);
        uint8_t decode_result[min_decode_buff_size];
        size_t out_size = dap_enc_decode(key,
                                         encrypt_result,
                                         encrypted_size,
                                         decode_result,
                                         min_decode_buff_size,
                                         data_type);

        dap_assert_PIF(source_size == out_size, "Check result decode size");

        dap_assert_PIF(memcmp(source, decode_result, source_size) == 0, "Check source and encode->decode data");

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

static void _write_key_in_file(dap_enc_key_serealize_t* key,
                               const char* file_name)
{
    FILE *f = fopen(file_name, "w");
    dap_assert(f, "Can't create file");
    fwrite(key, sizeof (dap_enc_key_serealize_t), 1, f);
    fclose(f);
}

dap_enc_key_serealize_t* _read_key_from_file(const char* file_name)
{
    FILE *f = fopen(file_name, "r");
    dap_assert(f, "Can't open key file");
    dap_enc_key_serealize_t* resut_key = calloc(1, sizeof(dap_enc_key_serealize_t));
    fread(resut_key, sizeof(dap_enc_key_serealize_t), 1, f);
    fclose(f);
    return resut_key;
}

static void test_serealize_deserealize()
{
    const char *kex_data = "123";
    size_t kex_size = strlen(kex_data);
    const size_t seed_size = 1 + (rand() % 1000);
    uint8_t seed[seed_size];

    generate_random_byte_array(seed, seed_size);

    dap_enc_key_t* key = dap_enc_key_new_generate(DAP_ENC_KEY_TYPE_IAES, kex_data, kex_size, seed, seed_size, 0);
    dap_enc_key_serealize_t* serealize_key = dap_enc_key_serealize(key);
    _write_key_in_file(serealize_key, TEST_SER_FILE_NAME);
    dap_enc_key_serealize_t* deserealize_key = _read_key_from_file(TEST_SER_FILE_NAME);
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
}

void dap_enc_tests_run() {
    dap_print_module_name("dap_enc");
    init_test_case();
    test_encode_decode_raw(50);
    test_encode_decode_raw_b64(50);
    test_encode_decode_raw_b64_url_safe(50);
    test_key_transfer_msrln();
    dap_print_module_name("dap_enc serealize->deserealize");
    test_serealize_deserealize();
    cleanup_test_case();
}
