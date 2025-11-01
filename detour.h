#ifndef DETOUR_H
#define DETOUR_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif


#if !defined(__x86_64__) && !defined(_M_X64)
#error "detour: only x86_64 is supported by this implementation"
#endif

typedef struct detour {
    void *original;           /* pointer to original function */
    void *detour;             /* pointer to detour function */
    void *trampoline;         /* allocated trampoline memory */
    uint8_t original_code[32];/* buffer to save stolen bytes */
    size_t stolen_bytes;      /* number of bytes overwritten at original */
} detour_t;

int detour_init(detour_t *detour, void *original, void *detour_func);

int detour_install(detour_t *detour);

int detour_remove(detour_t *detour);

void detour_cleanup(detour_t *detour);

#ifdef __cplusplus
}
#endif

#endif /* DETOUR_H */
