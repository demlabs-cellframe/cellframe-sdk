#ifndef _WIN32
#include "dap_circular_test.h"
#include "dap_circular_buffer.h"

#include <string.h>
#include <sys/socket.h>
#include <unistd.h>


static char *chars_string = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";

#define MAX_RESULT_BUF_LEN 8096
void dap_circular_test_simple()
{
    const int buf_size = 8;
    circular_buffer_t cb = circular_buffer_create(buf_size);

    circular_buffer_push(cb, chars_string, buf_size);

    int fd[2];
    socketpair(PF_LOCAL, SOCK_STREAM, 0, fd);

    int ret = circular_buffer_write_In_socket(cb, fd[0]);
    dap_assert(ret == buf_size, "Check ret write in socket");

    ret = circular_buffer_write_In_socket(cb, fd[0]);
    dap_assert(ret == 0, "Check ret write in socket");
    char result_buff[MAX_RESULT_BUF_LEN] = {0};
    ssize_t res = read(fd[1], result_buff, 44);

    dap_assert(res == buf_size, "Check buf size");

    dap_assert(dap_strn_equals(result_buff, chars_string, buf_size),
               "Check result buf");
    dap_assert(circular_buffer_get_data_size(cb) == 0, "Check data size");

    close(fd[0]);
    close(fd[1]);
    circular_buffer_free(cb);
    dap_pass_msg("Test simple");
}

void dap_circular_test_double_write()
{
    const int buf_size = 8;
    const char* expected_string = "0123456701";
    int expected_string_len = strlen(expected_string);
    circular_buffer_t cb = circular_buffer_create(buf_size);

    circular_buffer_push(cb, chars_string, buf_size);

    int fd[2];
    socketpair(PF_LOCAL, SOCK_STREAM, 0, fd);

    int ret = circular_buffer_write_In_socket(cb, fd[0]);

    circular_buffer_push(cb, chars_string, 2);

    ret = circular_buffer_write_In_socket(cb, fd[0]);
    dap_assert(ret == 2, "Check ret write in socket");

    char result_buff[MAX_RESULT_BUF_LEN] = {0};
    ssize_t res = read(fd[1], result_buff, 44);

    dap_assert(res == expected_string_len, "Check buf size");

    dap_assert(dap_str_equals(result_buff, expected_string),
               "Check result buf");
    dap_assert(circular_buffer_get_data_size(cb) == 0, "Check data size");
    dap_pass_msg("Double write");

    circular_buffer_free(cb);
    close(fd[0]);
    close(fd[1]);
}

void dap_circular_test_defrag_write()
{
    const int buf_size = 8;
    const char* expected_string = "56701201";
    int expected_string_len = strlen(expected_string);
    circular_buffer_t cb = circular_buffer_create(buf_size);

    circular_buffer_push(cb, chars_string, buf_size);
    circular_buffer_pop(cb, 5, NULL);
    circular_buffer_push(cb, chars_string, 3);
    // expected string here 567012


    int fd[2];
    socketpair(PF_LOCAL, SOCK_STREAM, 0, fd);

    // write 567012
    int ret = circular_buffer_write_In_socket(cb, fd[0]);
    dap_assert(ret == 6, "Check ret write in socket");

    // push 01
    circular_buffer_push(cb, chars_string, 2);

    // write 01
    ret = circular_buffer_write_In_socket(cb, fd[0]);
    dap_assert(ret == 2, "Check ret write in socket");

    char result_buff[MAX_RESULT_BUF_LEN] = {0};
    ssize_t res = read(fd[1], result_buff, MAX_RESULT_BUF_LEN);

    dap_assert(res == expected_string_len, "Check buf size");

    dap_assert(dap_str_equals(result_buff, expected_string),
               "Check result buf");

    dap_pass_msg("Double write");
    dap_assert(circular_buffer_get_data_size(cb) == 0, "Check data size");
    circular_buffer_free(cb);
    close(fd[0]);
    close(fd[1]);
}

void dap_circular_test_write_bad_socket()
{
    const int buf_size = 8;
    circular_buffer_t cb = circular_buffer_create(buf_size);

    circular_buffer_push(cb, chars_string, buf_size);

    int fd[2];
    socketpair(PF_LOCAL, SOCK_STREAM, 0, fd);
    int fd2[2];
    socketpair(PF_LOCAL, SOCK_STREAM, 0, fd2);

    close(fd[0]);
    int ret = circular_buffer_write_In_socket(cb, fd[0]);
    dap_assert(ret == -1, "Check ret write in socket");

    ret = circular_buffer_write_In_socket(cb, fd2[0]);
    dap_assert(ret == 8, "Check ret write in socket");
    char result_buff[MAX_RESULT_BUF_LEN] = {0};
    ssize_t res = read(fd2[1], result_buff, MAX_RESULT_BUF_LEN);

    dap_assert(res == buf_size, "Check buf size");

    dap_assert(dap_strn_equals(result_buff, chars_string, buf_size),
               "Check result buf");

    ret = circular_buffer_write_In_socket(cb, fd2[0]);
    dap_assert(ret == 0, "Check zero write");
    dap_assert(circular_buffer_get_data_size(cb) == 0, "Check data size");
    close(fd[1]);
    close(fd2[0]);
    close(fd2[1]);
    circular_buffer_free(cb);
    dap_pass_msg("Test simple");
}

void dap_circular_load_test()
{
    srand(time(NULL));

    int iterations = 230;

    const char *digits = "123456789";

    const int buf_size = strlen(digits);
    circular_buffer_t cb = circular_buffer_create(buf_size);

    int fd[2];
    socketpair(PF_LOCAL, SOCK_STREAM, 0, fd);

    int count_writed_bytes = 0;

    // defrag buffer
    circular_buffer_push(cb, (void*)digits, strlen(digits));
    circular_buffer_pop(cb, strlen(digits) - 1, NULL);
    circular_buffer_push(cb, (void*)digits, 3);
    count_writed_bytes = 4;

    char expectedBuffer[MAX_RESULT_BUF_LEN];
    memset(expectedBuffer, 0, MAX_RESULT_BUF_LEN);
    circular_buffer_read(cb, count_writed_bytes, expectedBuffer);

    int count_write_bytes = 4;
    do {
        int r = circular_buffer_write_In_socket(cb, fd[0]);
        dap_assert_PIF(r == count_write_bytes, "Check write bytes");
        dap_assert_PIF(circular_buffer_get_data_size(cb) == 0, "buf size must be 0!");

        count_write_bytes = rand() % strlen(digits);
        circular_buffer_push(cb, (void*)digits, count_write_bytes);
        strncat(expectedBuffer, digits, count_write_bytes);
        count_writed_bytes += count_write_bytes;
    } while (--iterations);
    count_writed_bytes -= count_write_bytes; // last bytes will not be writed

    char result_buff[MAX_RESULT_BUF_LEN] = {0};
    ssize_t res = read(fd[1], result_buff, MAX_RESULT_BUF_LEN);
    dap_assert(res == count_writed_bytes, "Check count writed and readed from socket bytes");

    dap_assert(memcmp(expectedBuffer, result_buff, res) == 0, "Check expected and result buffer");

    circular_buffer_free(cb);
    close(fd[0]);
    close(fd[1]);
}
void dap_circular_test_run()
{
    dap_print_module_name("dap_circular");

    dap_circular_test_simple();
    dap_circular_test_double_write();
    dap_circular_test_defrag_write();
#ifdef __linux__
    dap_circular_test_write_bad_socket();
    dap_circular_load_test();
#endif
}
#endif