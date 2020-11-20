#include<stdlib.h>
#include<stdint.h>
#include <errno.h>


#ifndef PROJECT1_HEAP_H
#define PROJECT1_HEAP_H
#define PAGE_SIZE       4096    // Długość strony w bajtach
#define PAGES_AVAILABLE 16384   // Liczba stron dostępnych dla sterty

#define FENCE_SIZE 16

enum pointer_type_t
{
    pointer_null,
    pointer_heap_corrupted,
    pointer_control_block,
    pointer_inside_fences,
    pointer_inside_data_block,
    pointer_unallocated,
    pointer_valid
};
struct memory_block_t{
    struct memory_block_t *next;
    struct memory_block_t *prev;
    size_t bias;
    size_t size;
    size_t free;
};
struct memory_menager_t{
    struct memory_block_t *head;
    struct memory_block_t *tail;
    void * memory;
    int initialized;
    size_t size;
    size_t in_use;
};

#define BLOCK_SIZE sizeof(struct memory_block_t)

#define ALIGNED 8
int align_size(int size);
int heap_setup(void);
void heap_clean(void);
void* heap_malloc(size_t size);
void* heap_calloc(size_t number, size_t size);
void* heap_realloc(void* memblock, size_t count);
void  heap_free(void* memblock);
size_t   heap_get_largest_used_block_size(void);
enum pointer_type_t get_pointer_type(const void* const pointer);
int heap_validate(void);
void* heap_malloc_aligned(size_t count);
void* heap_calloc_aligned(size_t number, size_t size);
void* heap_realloc_aligned(void* memblock, size_t size);
int extend_heap(size_t pages);
struct memory_block_t* get_first_fittimg(size_t size);
struct memory_block_t* get_first_fittimg_aligned(size_t size);
struct memory_block_t* createBlock(void* adress,size_t size);
void printHeap();
#endif //PROJECT1_HEAP_H
