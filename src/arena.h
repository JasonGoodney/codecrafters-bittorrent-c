#ifndef ARENA_H
#define ARENA_H

#include <stdlib.h>

#define DEFAULT_ALIGNMENT (2 * sizeof(void *))

struct arena {
    void *base;
    size_t size;
    size_t offset;
    size_t used;
};

#define is_power_of_two(x) ((x != 0) && ((x & (x - 1)) == 0))

void *
arena_push(struct arena *arena, size_t size, size_t nitems);
struct arena
arena_init(uint32_t capacity);
void
arena_destroy(struct arena *arena);
void
arena_free(size_t size, void *ptr, void *context);
void
arena_free_all(void *arena);

static uintptr_t
align_forward(uintptr_t ptr, size_t alignment)
{
    uintptr_t p;
    uintptr_t a;
    uintptr_t modulo;

    if (!is_power_of_two(alignment)) {
        return 0;
    }

    p = ptr;
    a = (uintptr_t)alignment;
    modulo = p & (a - 1);

    if (modulo) {
        p += a - modulo;
    }

    return p;
}

static void *
arena_alloc_aligned(struct arena *a, size_t size, size_t alignment)
{
    uintptr_t curr_ptr = (uintptr_t)a->base + (uintptr_t)a->offset;
    uintptr_t offset = align_forward(curr_ptr, alignment);
    offset -= (uintptr_t)a->base;

    if (offset + size > a->size) { // out of bounds
        return 0;
    }

    void *ptr = (uint8_t *)a->base + offset;
    a->used += size;
    a->offset = offset + size;

    return ptr;
}

static void *
arena_alloc(size_t size, void *context)
{
    if (!size) {
        return 0;
    }

    void *ptr =
        arena_alloc_aligned((struct arena *)context, size, DEFAULT_ALIGNMENT);
    return ptr;
}

void *
arena_push(struct arena *arena, size_t size, size_t nitems)
{
    return arena_alloc(size * nitems, arena);
}

struct arena
arena_init(uint32_t capacity)
{
    struct arena arena = {0};
    arena.size = capacity;
    arena.base = malloc(capacity);
    return arena;
}

void
arena_destroy(struct arena *arena)
{
    free(arena->base);
}

void
arena_free(size_t size, void *ptr, void *context)
{
    (void)size;
    (void)ptr;
    (void)context;
}

void
arena_free_all(void *arena)
{
    struct arena *a = arena;
    a->offset = 0;
    a->used = 0;
}

#endif // ARENA_H
