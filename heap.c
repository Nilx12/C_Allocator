#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <math.h>
#include "heap.h"

struct memory_menager_t memory_menager = {NULL,NULL,0,0,0,0};
int heap_setup(void){

    errno = 0;
    void *memory_a = sbrk(0);
    if(errno == 12){
        return 1;
    }
    memory_menager.memory = memory_a;
    memory_menager.size = 0;
    memory_menager.initialized = 1;
    return 0;
}
void heap_clean(void){
    memory_menager.memory = NULL;
    memory_menager.head = NULL;
    sbrk(-1 * memory_menager.size);
    memory_menager.size = 0;
    memory_menager.initialized = 0;

}
void* heap_malloc(size_t size){

    if(size == 0 || heap_validate() != 0){
        return NULL;
    }

    struct memory_block_t *block = memory_menager.head;
    size_t size_total = align_size(size) + FENCE_SIZE * 2 + BLOCK_SIZE;
    if(block == NULL){
        if(size_total > memory_menager.size) {
            size_t pages_nedded = ceil((double) (size_total - memory_menager.size) / PAGE_SIZE);
            int error = extend_heap(pages_nedded);
            if (error != 0) {
                return NULL;
            }
        }
        struct memory_block_t *new_block = createBlock(memory_menager.memory,size);
        memory_menager.head = new_block;
        memory_menager.tail = new_block;
        memory_menager.in_use += size_total;
        char *ptr = (char*)new_block + BLOCK_SIZE + FENCE_SIZE;

        return ptr;
    }
    struct memory_block_t *new_block = get_first_fittimg(size);
    if(new_block != NULL){
        new_block->free = 0;

       if( ((long)size + (long)BLOCK_SIZE*2 + 4*(long)FENCE_SIZE) < (long)new_block->size) {

            size_t size_rets = (long)new_block->size - ((long)size + (long)BLOCK_SIZE + 2*(long)FENCE_SIZE);
            struct memory_block_t *block_cut = createBlock((char *) new_block + (long)BLOCK_SIZE + (long)FENCE_SIZE * 2 + (long)size,
                                                           size_rets);
            block_cut->next = new_block->next;
            block_cut->prev = new_block;
            new_block->next->prev = block_cut;
            new_block->next = block_cut;
            block_cut->free = 1;
            block_cut->bias = block_cut->size + block_cut->free;
        }
        new_block->size = size;
        new_block->bias = size;
        memset((char*)new_block + (long)BLOCK_SIZE + (long)FENCE_SIZE + (long)size,'#',FENCE_SIZE);
        memset((char*)new_block + (long)BLOCK_SIZE,'#',FENCE_SIZE);


        return (char*)new_block + BLOCK_SIZE + FENCE_SIZE;
    }
    if(memory_menager.in_use + size_total > memory_menager.size) {
        size_t pages_nedded = ceil((double) ((memory_menager.in_use + size_total) - memory_menager.size) / (double)PAGE_SIZE);
        int error = extend_heap(pages_nedded);
        if (error != 0) {
            return NULL;
        }
    }
    new_block = createBlock((char *)memory_menager.tail + BLOCK_SIZE + FENCE_SIZE*2 + memory_menager.tail->size,size);
    new_block->prev = memory_menager.tail;
    memory_menager.tail->next = new_block;
    memory_menager.tail = new_block;
    memory_menager.in_use += size_total;

    return (char*)new_block + BLOCK_SIZE + FENCE_SIZE;
}
void* heap_calloc(size_t number, size_t size){
    if(size == 0 || number <= 0 || heap_validate() != 0){
        return NULL;
    }
    char *ptr = heap_malloc(size*number);
    if(ptr == NULL){
        return NULL;
    }
    memset(ptr,0,size*number);
    return ptr;
}
void* heap_realloc(void* memblock, size_t count){
    int val = heap_validate();

    if(val != 0 || ( get_pointer_type(memblock) != pointer_valid && get_pointer_type(memblock) != pointer_null && get_pointer_type(memblock)  != pointer_unallocated )){

        return NULL;
    }

    if(count == 0){
        heap_free(memblock);
        return NULL;
    }
    if(memblock == NULL){
        void* tmp= heap_malloc(count);
        return tmp;
    }
    struct memory_block_t *block = (void*)((char*)memblock - FENCE_SIZE - BLOCK_SIZE);
    if(block->size >= count){
        block->size = count;
        block->bias = block->size;
        char *ptr = (char *)block + BLOCK_SIZE;
        memset(ptr,'#',FENCE_SIZE);
        memset(ptr + FENCE_SIZE + block->size,'#',FENCE_SIZE);


        return memblock;
    }
    size_t unused_bytes = block->size;
    if(block->next != NULL){
        unused_bytes = ((long)block->next - FENCE_SIZE) - ((long)block + BLOCK_SIZE + FENCE_SIZE);
    }

    if(block->next != NULL && block->next->free == 1 && (long)BLOCK_SIZE + 2* (long)FENCE_SIZE +(long)unused_bytes+ (long)block->next->size >= (long)count){

        if((long)unused_bytes + (long) block->next->size +  (long)FENCE_SIZE*2 +  (long)BLOCK_SIZE - (long)count> (long)FENCE_SIZE*2 +  (long)BLOCK_SIZE){
            size_t cut_position = (long)block + count + BLOCK_SIZE + 2*FENCE_SIZE;
            size_t remaining_bytes = (long)unused_bytes + (long)block->next->size - (long)count;
            struct memory_block_t *next = block->next->next, *prev = block->next->prev;
            struct memory_block_t *new_block = createBlock((void*)cut_position ,remaining_bytes);
            new_block->next = next;
            new_block->prev = prev;
            new_block->next->prev = new_block;
            new_block->free = 1;
            new_block->bias = new_block->size + 1;
            block->next = new_block;
        } else {
            block->next->next->prev = block;
            block->next = block->next->next;
        }
        block->size = count;
        block->bias = count;
        memset((char *)memblock + block->size,'#',FENCE_SIZE);

        heap_validate();
        return memblock;
    }
    if(block->next != NULL) {
        void *tmp = heap_malloc(count);
        if (tmp == NULL) {
            return NULL;
        }
        memcpy(tmp, memblock, block->size);
        heap_free(memblock);
        return tmp;
    }
    if( (long)memory_menager.in_use + (long)count - (long)block->size > (long)memory_menager.size){
        size_t pages_nedded = ceil((double) ((long)memory_menager.in_use + (long)count -(long) block->size  - (long)memory_menager.size) / PAGE_SIZE);
        int error = extend_heap(pages_nedded);
        if (error != 0) {
            return NULL;
        }
    }
    memory_menager.in_use +=  count - block->size;
    block->size = count;
    block->bias = count;
    memset((char *)memblock + count,'#',FENCE_SIZE);

    return memblock;
}
void  heap_free(void* memblock){
    if(memblock == NULL || heap_validate() != 0 || get_pointer_type(memblock) != pointer_valid){
        return;
    }
    struct memory_block_t *block = (void*)((char*)memblock -  (long)FENCE_SIZE -  (long)sizeof(struct memory_block_t));
    if(block->free != 0){

        return;
    }
    block->free = 1;
    if(block->next != NULL){
        block->size = ((long)block->next -  (long)FENCE_SIZE) - (long)((long)block +  (long)BLOCK_SIZE +  (long)FENCE_SIZE);
        block->bias = block->size + block->free;
        char *ptr = (char *)block + BLOCK_SIZE;
        memset(ptr,'#',FENCE_SIZE);
        memset(ptr + FENCE_SIZE + block->size,'#',FENCE_SIZE);
    }
    if(block->prev == NULL && block->next == NULL){
        memory_menager.head = NULL;
        memory_menager.tail = NULL;
        memory_menager.in_use = 0;
        return;
    }


    if(block->prev == NULL && block->next != NULL && block->next->free == 1){

        block->size = ((long)block->next->next -  (long)FENCE_SIZE) - (long)((long)block +  (long)BLOCK_SIZE +  (long)FENCE_SIZE);
        block->bias = block->size + block->free;
        block->next->next->prev = block;
        block->next = block->next->next;
        char *ptr = (char *)block + BLOCK_SIZE;
        memset(ptr,'#',FENCE_SIZE);
        memset(ptr + FENCE_SIZE + block->size,'#',FENCE_SIZE);


        return;
    }
    //Blok w środku pamieci
    if(block->prev != NULL && block->next != NULL && block->prev->free == 1 && block->next->free == 1){

        block->prev->size = (long)((long)block->next->next - (long)FENCE_SIZE) - (long)( (long)block->prev + (long)BLOCK_SIZE + (long)FENCE_SIZE);
        block->prev->bias = block->prev->size + block->prev->free;
        block->next->next->prev = block->prev;
        block->prev->next = block->next->next;
        char *ptr = (char *)block->prev + BLOCK_SIZE;
        memset(ptr,'#',FENCE_SIZE);
        memset(ptr + FENCE_SIZE + block->prev->size,'#',FENCE_SIZE);

        return;
    }

    if(block->prev != NULL && block->next != NULL && block->next->free == 1){
        block->size = ((long)block->next->next -  (long)FENCE_SIZE) - (long)((long)block +  (long)BLOCK_SIZE +  (long)FENCE_SIZE);
        block->bias = block->size + block->free;
        block->next->next->prev = block;
        block->next = block->next->next;
        char *ptr = (char *)block + BLOCK_SIZE;
        memset(ptr,'#',FENCE_SIZE);
        memset(ptr + FENCE_SIZE + block->size,'#',FENCE_SIZE);

        return;
    }

    if(block->prev != NULL && block->next != NULL && block->prev->free == 1){
        //if(block->next->next == NULL) {
            block->prev->size = (long)((long) block->next -  (long)FENCE_SIZE) - (long) ( (long)block->prev +  (long)BLOCK_SIZE +  (long)FENCE_SIZE);

/*        }else{
            block->prev->size = (long) block->next->next -  (long)FENCE_SIZE - (long) ( (long)block +  (long)BLOCK_SIZE +  (long)FENCE_SIZE);
        }*/
        block->prev->bias = block->prev->size + block->prev->free;
        block->next->prev = block->prev;
        block->prev->next = block->next;
         char *ptr = (char *)block->prev + BLOCK_SIZE;
        memset(ptr,'#',FENCE_SIZE);
        memset(ptr + FENCE_SIZE + block->prev->size,'#',FENCE_SIZE);

        return;
    }

    //Blok na koncu pamięci
    if(block->next == NULL && block->prev != NULL && block->prev->free == 0){
        block->prev->next = NULL;
        memory_menager.tail = block->prev;
        memory_menager.in_use -= ( (long)block->size +  (long)FENCE_SIZE*2 +  (long)BLOCK_SIZE);
        return;
    }

    if(block->next == NULL && block->prev != NULL && block->prev->free == 1 && block->prev->prev == NULL){
        memory_menager.head = NULL;
        memory_menager.tail = NULL;
        memory_menager.in_use = 0;
        return;
    }

    if(block->next == NULL && block->prev != NULL && block->prev->free == 1 && block->prev->prev != NULL){

        block->prev->prev->next = NULL;
        memory_menager.tail = block->prev->prev;
        memory_menager.in_use -= ( (long)block->size +  (long)block->prev->size +  (long)FENCE_SIZE*4 +  (long)BLOCK_SIZE*2);
        return;
    }


}
size_t   heap_get_largest_used_block_size(void){
    if(memory_menager.initialized != 1 || memory_menager.head == NULL || heap_validate() != 0){
        return 0;
    }
    struct memory_block_t *block = memory_menager.head;
    size_t size=0;
    while (block != NULL){
        if (block->free == 0){
            if(block->size > size){
                size = block->size;
            }
        }
        block = block->next;
    }
    return size;
}
enum pointer_type_t get_pointer_type(const void* const pointer){
    if(pointer == NULL){
        return pointer_null;
    }
    if(pointer < memory_menager.memory || (long )pointer > (long)memory_menager.memory + (long)memory_menager.size){
        return pointer_heap_corrupted;
    }
    const struct memory_block_t *block = memory_menager.head;
    char *ptr;
    enum pointer_type_t point = pointer_null;
    while (block != NULL){
        ptr = (char *) block + BLOCK_SIZE + FENCE_SIZE;
        if (ptr == pointer){
            point = pointer_valid;
            break;
        }
        if((long)pointer >= (long)(char *)block && (long)pointer < (long) ptr - (long)FENCE_SIZE){
            point =  pointer_control_block;
            break;
        }
        if((long)pointer > (long) ptr  && (long)pointer < (long) ptr + (long) block->size){
            point = pointer_inside_data_block;
            break;
        }
        if(((long)pointer < (long) ptr  && (long)pointer >= (long) block + (long)BLOCK_SIZE )
        || (long)pointer >= (long) ptr + (long)block->size &&(long)pointer < (long) ptr + (long)block->size + (long)FENCE_SIZE ) {
            point = pointer_inside_fences;
            break;
        }

        block = block->next;
    }
    if(block == NULL) {
        return pointer_unallocated;
    }
    if(block->free == 0){
        return point;
    }else if(block->free == 1){
        return pointer_unallocated;
    }else{
        return pointer_heap_corrupted;
    }

    return 7;
}
int heap_validate(void){
    if(memory_menager.initialized == 0){
        return 2;
    }
    size_t index = 0;
    struct memory_block_t *block = memory_menager.head;
    char *ptr;

    while (block != NULL){

        if((block != memory_menager.head && block->prev == NULL) ||
            (block != memory_menager.tail && block->next == NULL) ||
            ((block->next != NULL) && ((long)block->next < (long)memory_menager.memory || (long)block->next > (long)memory_menager.memory + (long)memory_menager.in_use)) ||
            ((block->prev != NULL) && ((long)block->prev < (long)memory_menager.memory || (long)block->prev > (long)memory_menager.memory + (long)memory_menager.in_use)) ||
            (block->next != NULL && block->next->prev != block) ||
            (block->prev != NULL && block->prev->next != block) ||
            (block->size + block->free != block->bias) ||
            (block->free != 1 && block->free != 0) ||
            (block->size > memory_menager.in_use)){

                return 3;
        }
        ptr = (char *)block + sizeof(struct memory_block_t) + FENCE_SIZE;
        for (int i = 0; i < FENCE_SIZE; ++i) {
            if((*(ptr - FENCE_SIZE + i) != '#' || *(ptr + block->size + i) != '#')){
                return 1;
            }
        }
        index ++;
        block = block->next;
    }
    return 0;
}
void* heap_malloc_aligned(size_t count){
    if(count == 0 || heap_validate() != 0){
        return NULL;
    }
    if(memory_menager.head == NULL){
        size_t pages_nedded = ceil((double) (count) / PAGE_SIZE) + 1;
        if( extend_heap(pages_nedded)){
            return NULL;
        }
        struct memory_block_t *block =  createBlock(memory_menager.memory,PAGE_SIZE - BLOCK_SIZE * 2 - FENCE_SIZE*3);
        memory_menager.head = block;
        struct memory_block_t *block_alligned = createBlock((char*)memory_menager.memory + PAGE_SIZE - BLOCK_SIZE - FENCE_SIZE,count);
        memory_menager.tail = block_alligned;
        block->next = block_alligned;
        block->free = 1;
        block->bias = block->size + block->free;
        block_alligned->prev = block;
        block_alligned->free = 0;
        block_alligned->bias = block_alligned->free + block_alligned->size;
        char *ptr = (char*)block_alligned + BLOCK_SIZE + FENCE_SIZE;
        memory_menager.in_use = (long)((long)block_alligned - (long)memory_menager.memory)+BLOCK_SIZE + block_alligned->size + FENCE_SIZE*2;
        //printHeap();
        return ptr;
    }
    struct memory_block_t *block = get_first_fittimg_aligned(count);
    if(block == NULL){
     //   struct memory_block_t *bloczek = memory_menager.tail;

        //long mem = ((long)memory_menager.tail +(long)memory_menager.tail->size + FENCE_SIZE*2 + BLOCK_SIZE - (long)memory_menager.memory )+ (long)memory_menager.tail->size + FENCE_SIZE*2 + BLOCK_SIZE;
        long mem = ((long)memory_menager.tail +(long)memory_menager.tail->size + FENCE_SIZE*2 + BLOCK_SIZE - (long)memory_menager.memory );
        //size_t sos = (mem + BLOCK_SIZE + FENCE_SIZE) % PAGE_SIZE;
        if ((mem + BLOCK_SIZE + FENCE_SIZE) % PAGE_SIZE != 0){
            mem += PAGE_SIZE - ((mem + BLOCK_SIZE + FENCE_SIZE) % PAGE_SIZE);
        }
        if(mem + BLOCK_SIZE + FENCE_SIZE*2 + count > memory_menager.size){
            size_t pages_nedded = ceil((double) (mem + BLOCK_SIZE + FENCE_SIZE*2 + count - (long)memory_menager.size) / PAGE_SIZE) + 1;
            if( extend_heap(pages_nedded)){
                return NULL;
            }
        }
          size_t sos = (char *) memory_menager.memory + mem - ((char*) memory_menager.tail + FENCE_SIZE*2 + BLOCK_SIZE + (long)memory_menager.tail->size);
       if(sos > count + BLOCK_SIZE + FENCE_SIZE*2 ) {
             struct memory_block_t *block_empty = createBlock(
                     (char *) memory_menager.tail + FENCE_SIZE * 2 + BLOCK_SIZE + (long) memory_menager.tail->size,
                     //(long)( ((char*)memory_menager.memory + mem ) - ((char*)memory_menager.tail + FENCE_SIZE*2 + BLOCK_SIZE + (long)memory_menager.tail->size) - 2*FENCE_SIZE - BLOCK_SIZE )
                     (long)sos  - (long)BLOCK_SIZE - (long)FENCE_SIZE*2);
             //size_t a = (long) block_empty->size;
             block_empty->free = 1;
             memory_menager.tail->next = block_empty;
             block_empty->prev = memory_menager.tail;
             memory_menager.tail = block_empty;
             block_empty->bias = block_empty->free + block_empty->size;
         }
        struct memory_block_t *block_alligned = createBlock((char *) memory_menager.memory + mem, count);
        memory_menager.tail->next = block_alligned;
        block_alligned->prev = memory_menager.tail;
        memory_menager.tail = block_alligned;

        block_alligned->bias = block_alligned->free + block_alligned->size;

        memory_menager.in_use = (long)((long)block_alligned - (long)memory_menager.memory)+BLOCK_SIZE + block_alligned->size + FENCE_SIZE*2;
        char *ptr = (char*)block_alligned + BLOCK_SIZE + FENCE_SIZE;
        return ptr;
    }else{
        block->free = 0;
        block->size = count;
        block->bias = count;
        memset((char*)block + (long)BLOCK_SIZE + (long)FENCE_SIZE + (long)count,'#',FENCE_SIZE);
        memset((char*)block + (long)BLOCK_SIZE,'#',FENCE_SIZE);
       // printHeap();
        return (char*)block + BLOCK_SIZE + FENCE_SIZE;
    }
    return NULL;
}
void* heap_calloc_aligned(size_t number, size_t size){
    if(size == 0 || number <= 0 || heap_validate() != 0){
        return NULL;
    }
    char *ptr = heap_malloc_aligned(size*number);
    if(ptr == NULL){
        return NULL;
    }
    memset(ptr,0,size*number);
    return ptr;
}
void* heap_realloc_aligned(void* memblock, size_t size){
    if(heap_validate() != 0 || (get_pointer_type(memblock) != pointer_valid && get_pointer_type(memblock) != pointer_null )){
        return NULL;
    }
    struct memory_block_t *block =(void*)( (char*)memblock - BLOCK_SIZE - FENCE_SIZE);
    if(memblock == NULL){
        return heap_malloc_aligned(size);
    }
    if(size == 0){
        heap_free(memblock);
        return NULL;
    }
    if(size <= block ->size){
        block->size = size;
        block->bias = size;
        memset((char*)memblock + size,'#',FENCE_SIZE);
        return  memblock;
    }
    if(((long)memblock%PAGE_SIZE) != 0){
        void *ptr = heap_malloc_aligned(size);
        memcpy(ptr,memblock,block->size);
        heap_free(memblock);
        return ptr;
    }
    size_t unused_bytes = block->size;
    if(block->next != NULL){
        unused_bytes = ((long)block->next - FENCE_SIZE) - ((long)block + BLOCK_SIZE + FENCE_SIZE);
    }
    if(unused_bytes >= size){
        block->size = size;
        block->bias = size;
        memset((char*)memblock + size,'#',FENCE_SIZE);
        return memblock;
    }

    if(block->next != NULL && block->next->next != NULL && block->next->free == 1 && (long)BLOCK_SIZE + 2* (long)FENCE_SIZE +(long)unused_bytes + (long)block->next->size >= (long)size){

        if((long)unused_bytes + (long) block->next->size +  (long)FENCE_SIZE*2 +  (long)BLOCK_SIZE - (long)size> (long)FENCE_SIZE*2 +  (long)BLOCK_SIZE){
            size_t cut_position = (long)block + size + BLOCK_SIZE + 2*FENCE_SIZE;
            size_t remaining_bytes = (long)unused_bytes + (long)block->next->size - (long)size;
            struct memory_block_t *next = block->next->next, *prev = block->next->prev;
            struct memory_block_t *new_block = createBlock((void*)cut_position ,remaining_bytes);
            new_block->next = next;
            new_block->prev = prev;
            new_block->next->prev = new_block;
            new_block->free = 1;
            new_block->bias = new_block->size + 1;
            block->next = new_block;
        } else {
            block->next->next->prev = block;
            block->next = block->next->next;
        }

        block->size = size;
        block->bias = size;
        memset((char *)memblock + block->size,'#',FENCE_SIZE);

        return memblock;
    }
    if(block->next != NULL) {
        void *tmp = heap_malloc_aligned(size);
        if (tmp == NULL) {
            return NULL;
        }
        memcpy(tmp, memblock, block->size);
        heap_free(memblock);
        return tmp;
    }
    if( (long)memory_menager.in_use + (long)size - (long)block->size > (long)memory_menager.size){
        size_t pages_nedded = ceil((double) ((long)memory_menager.in_use + (long)size -(long) block->size  - (long)memory_menager.size) / PAGE_SIZE);
        int error = extend_heap(pages_nedded);
        if (error != 0) {
            return NULL;
        }
    }
    memory_menager.in_use +=  size - block->size;
    block->size = size;
    block->bias = size;
    memset((char *)memblock + size,'#',FENCE_SIZE);

    return memblock;
}

int extend_heap(size_t pages){
    if(memory_menager.size + pages*PAGE_SIZE >= PAGES_AVAILABLE*PAGE_SIZE  || pages > PAGES_AVAILABLE) {
        return 1;
    }
    errno = 0;
    sbrk(pages * PAGE_SIZE);
    if(errno == ENOMEM){
        return 1;
    }
    memory_menager.size += pages * PAGE_SIZE;
    return 0;
}

struct memory_block_t* get_first_fittimg(size_t size){

    struct memory_block_t *block = memory_menager.head;
    while (block != NULL){
        if(block->free == 1 && block->size >= size){
            return block;
        }
        block = block->next;
    }
    return NULL;
}
struct memory_block_t* createBlock(void* adress,size_t size){
    if(adress == NULL || size <= 0){
        return NULL;
    }
    struct memory_block_t *block = adress;
    memset(block,0,BLOCK_SIZE);
    char *ptr = (char *)adress + BLOCK_SIZE;
    memset(ptr,'#',FENCE_SIZE);
    memset(ptr + FENCE_SIZE + size,'#',FENCE_SIZE);
    block->size = size;
    block->free = 0;
    block->bias = size;
    block->next = NULL;
    block->prev = NULL;
    return block;
}
int align_size(int size){
    return (size + ALIGNED - 1)& ~(ALIGNED - 1);
}
void printHeap(){
    struct memory_block_t *block = memory_menager.head;
    while (block != NULL){
        printf("{%zu -> %zu} ",block->free,block->size);
        block = block->next;
    }
    printf("\n");
}

struct memory_block_t* get_first_fittimg_aligned(size_t size){

    struct memory_block_t *block = memory_menager.head;
    while (block != NULL){
        char * ptr = (char*)block + BLOCK_SIZE + FENCE_SIZE;
        if(block->free == 1 && block->size >= size && ((intptr_t)ptr & (intptr_t)(PAGE_SIZE -1)) == 0){
            return block;
        }
        if(block->free == 1 && block->size > size){
            long mem = ((long)block + FENCE_SIZE + BLOCK_SIZE) - (long)memory_menager.memory;
           // size_t sos = (char *) memory_menager.memory + mem - ((char*) memory_menager.tail + FENCE_SIZE*2 + BLOCK_SIZE + (long)memory_menager.tail->size);
           //long mem = (long)block - (long)memory_menager.memory;
            long mem2 = PAGE_SIZE - ((mem) % PAGE_SIZE);
            if(block->size >= PAGE_SIZE){
                if((long)size > (long)block->size - (long) mem2  || (long)memory_menager.memory + mem + mem2 - BLOCK_SIZE - FENCE_SIZE*2 < (long) block + FENCE_SIZE + BLOCK_SIZE){
                    break;
                }
                struct memory_block_t *tmp = createBlock((char*) memory_menager.memory + mem + mem2 - BLOCK_SIZE - FENCE_SIZE,size);
                tmp->next = block->next;
                tmp->prev = block;
                block->next->prev = tmp;
                block->next = tmp;
                block->size = ((long)tmp - FENCE_SIZE) - ((long) block + FENCE_SIZE + BLOCK_SIZE);
                block->bias = block->size + block->free;
                memset((char*) block +block->size +BLOCK_SIZE+ FENCE_SIZE,'#',FENCE_SIZE);
                memset((char*) block  +BLOCK_SIZE,'#',FENCE_SIZE);
                return tmp;
            }
        }
        block = block->next;
    }



    return NULL;
}
