#include "detour.h"

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <inttypes.h>

#if defined(_WIN32)
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#else
#include <sys/mman.h>
#include <unistd.h>
#include <errno.h>
#endif

static size_t detour_get_page_size(void)
{
#if defined(_WIN32)
    SYSTEM_INFO si;
    GetSystemInfo(&si);
    return (size_t)si.dwPageSize;
#else
    long p = sysconf(_SC_PAGESIZE);
    return (size_t)(p > 0 ? p : 4096);
#endif
}

static void *detour_alloc_exec(size_t size)
{
#if defined(_WIN32)
    return VirtualAlloc(NULL, size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
#else
    void *p = mmap(NULL, size, PROT_READ | PROT_WRITE | PROT_EXEC,
                   MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    return (p == MAP_FAILED) ? NULL : p;
#endif
}

static int detour_protect_rw(void *addr, size_t len)
{
#if defined(_WIN32)
    DWORD old;
    if (VirtualProtect(addr, len, PAGE_EXECUTE_READWRITE, &old))
        return 0;
    return -1;
#else
    size_t page = detour_get_page_size();
    uintptr_t start = (uintptr_t)addr & ~(page - 1);
    if (mprotect((void *)start, page, PROT_READ | PROT_WRITE | PROT_EXEC) == 0)
        return 0;
    return -1;
#endif
}

static void detour_free_exec(void *addr, size_t size)
{
#if defined(_WIN32)
    (void)size;
    VirtualFree(addr, 0, MEM_RELEASE);
#else
    munmap(addr, size);
#endif
}

static void detour_flush_icache(void *start, void *end)
{
#if defined(_WIN32)
    FlushInstructionCache(GetCurrentProcess(), start, (SIZE_T)((uintptr_t)end - (uintptr_t)start));
#else
    __builtin___clear_cache((char *)start, (char *)end);
#endif
}

int detour_init(detour_t *detour, void *original, void *detour_func)
{
    if (!detour || !original || !detour_func)
        return -1;

    memset(detour, 0, sizeof(detour_t));
    detour->original = original;
    detour->detour = detour_func;

    int64_t rel_off = (int64_t)((uint8_t *)detour_func - (uint8_t *)original - 5);
    if (rel_off >= INT32_MIN && rel_off <= INT32_MAX)
    {
        detour->stolen_bytes = 5;
    }
    else
    {
        detour->stolen_bytes = 14;
    }

    size_t tramp_size = 128;
    detour->trampoline = detour_alloc_exec(tramp_size);
    return 0;
}

int detour_install(detour_t *detour)
{
    if (!detour || !detour->original || !detour->detour || !detour->trampoline)
        return -1;
        
    memcpy(detour->original_code, detour->original, detour->stolen_bytes);

    if (detour_protect_rw(detour->original, detour->stolen_bytes) != 0)
    {
        return -1;
    }

    memcpy(detour->trampoline, detour->original_code, detour->stolen_bytes);

    uint8_t *jump = (uint8_t *)detour->trampoline + detour->stolen_bytes;
    uint64_t continue_addr = (uint64_t)((uint8_t *)detour->original + detour->stolen_bytes);

    jump[0] = 0x48;
    jump[1] = 0xB8;
    memcpy(&jump[2], &continue_addr, 8);
    jump[10] = 0xFF;
    jump[11] = 0xE0;

    uint8_t *target = (uint8_t *)detour->original;

    if (detour->stolen_bytes == 5)
    {
        int32_t rel = (int32_t)((int64_t)((uint8_t *)detour->detour - target - 5));
        target[0] = 0xE9;
        memcpy(&target[1], &rel, 4);
    }
    else
    {
        uint64_t detour_addr = (uint64_t)detour->detour;
        target[0] = 0x48;
        target[1] = 0xB8;
        memcpy(&target[2], &detour_addr, 8);
        target[10] = 0xFF;
        target[11] = 0xE0;
        for (size_t i = 12; i < detour->stolen_bytes; ++i)
            target[i] = 0x90;
    }

    detour_flush_icache(detour->trampoline, (uint8_t *)jump + 12);
    detour_flush_icache(detour->original, (uint8_t *)detour->original + detour->stolen_bytes);

    return 0;
}

int detour_remove(detour_t *detour)
{
    if (!detour || !detour->original)
        return -1;

    if (detour_protect_rw(detour->original, detour->stolen_bytes) != 0)
    {
        return -1;
    }

    memcpy(detour->original, detour->original_code, detour->stolen_bytes);
    detour_flush_icache(detour->original, (uint8_t *)detour->original + detour->stolen_bytes);
    return 0;
}

void detour_cleanup(detour_t *detour)
{
    if (!detour)
        return;
    if (detour->trampoline)
    {
        detour_free_exec(detour->trampoline, 128);
        detour->trampoline = NULL;
    }
}
