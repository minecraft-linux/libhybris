#ifndef HYBRIS_SIGSET_H
#define HYBRIS_SIGSET_H

#include <signal.h>

typedef unsigned int bionic_sigset_t;
typedef struct { unsigned long __bits[64/sizeof(unsigned long)/8]; } bionic_sigset64_t;

static inline void bionic_sigset_t_to_host(sigset_t *res, const bionic_sigset_t *in) {
    sigemptyset(res);
    for (int i = 0; i < sizeof(*in) * 8; i++) {
        if ((*in) & (1U << i))
            sigaddset(res, i);
    }
}
static inline void bionic_sigset_t_from_host(bionic_sigset_t *res, sigset_t *in) {
    *res = 0;
    for (int i = 0; i < sizeof(*in) * 8; i++) {
        if (sigismember(in, i))
            *res |= (1U | i);
    }
}
static inline void bionic_sigset64_t_to_host(sigset_t *res, const bionic_sigset64_t *in) {
    for (int j = 0; j < sizeof(in->__bits) / sizeof(unsigned long); j++) {
        for (int i = 0; i < sizeof(unsigned long) * 8; i++) {
            if (in->__bits[j] & (1LU << i))
                sigaddset(res, j * (sizeof(unsigned long) * 8) + i);
        }
    }
}
static inline void bionic_sigset64_t_from_host(bionic_sigset64_t *res, const sigset_t *in) {
    for (int j = 0; j < sizeof(res->__bits) / sizeof(unsigned long); j++) {
        for (int i = 0; i < sizeof(unsigned long) * 8; i++) {
            if (sigismember(in, j * (sizeof(unsigned long) * 8) + i))
                res->__bits[j] |= (1LU << i);
        }
    }
}

#endif //HYBRIS_SIGSET_H
