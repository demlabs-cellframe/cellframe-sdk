#include "dap_test_generator.h"

#define BYTE_SIZE 255

/**
 * @brief The function fills an array with random numbers
 * @param[out] array Takes a pointer to an array
 * @param[in] size Size of the array passed in the array parameter
 *
 * The function fills an array with random integer non-negative values
*/
void generate_random_byte_array(uint8_t* array, const size_t size) {
    srand((uint32_t)time(NULL));
    for(size_t i = 0; i < size; i++) {
        array[i] = (uint8_t)rand() % BYTE_SIZE;
    }

    // Last byte not should be 0
    if (array[size - 1] == 0)
        array[size - 1] = 1;
}
