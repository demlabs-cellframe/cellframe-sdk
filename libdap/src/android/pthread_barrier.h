#ifndef PTHREAD_BARRIER_H
#define PTHREAD_BARRIER_H

#include <pthread.h>

#if __ANDROID_API__ < __ANDROID_API_N__
typedef int pthread_barrierattr_t;
typedef struct
{
    pthread_mutex_t mutex;
    pthread_cond_t cond;
    int count;
    int tripCount;
} pthread_barrier_t;


int pthread_barrier_init(pthread_barrier_t *barrier, const pthread_barrierattr_t *attr, unsigned int count);

int pthread_barrier_destroy(pthread_barrier_t *barrier);

int pthread_barrier_wait(pthread_barrier_t *barrier);


#endif // PTHREAD_BARRIER_H
#endif // PTHREAD_BARRIER_H
