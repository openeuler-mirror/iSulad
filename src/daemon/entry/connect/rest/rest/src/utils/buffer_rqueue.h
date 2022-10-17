#include "rqueue.h"
#include "atomic_defs.h"

struct buffer {
    rqueue_t *rq;
    struct page *pg;
    int offset;
};

struct buffer *buffer_create(size_t size, rqueue_mode_t mode);

void buffer_destroy(void *buffer);

int buffer_read(struct buffer *buf, void *output, int nbytes);

int buffer_write(struct buffer *buf, void *output, int nbytes);

struct page {
    char *buf_ptr;
    int size;
};

void page_destroy(void *page); 

struct page * page_create(char *ptr, int size); 
