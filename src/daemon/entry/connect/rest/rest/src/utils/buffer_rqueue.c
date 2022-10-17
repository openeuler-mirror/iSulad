#include "buffer_rqueue.h"
#include <string.h>
#include <stdio.h>


struct buffer *buffer_create(size_t size, rqueue_mode_t mode)
{
    struct buffer *buf;
    rqueue_t *rq;

    buf = (struct buffer *)malloc(sizeof(struct buffer));
    rq = rqueue_create(size, RQUEUE_MODE_BLOCKING);
    //rqueue_set_free_value_callback(rq, destroy_page);
    buf->pg = NULL;
    buf->rq = rq;
    buf->offset = 0;

    return buf;
}

void buffer_destroy(void *buffer)
{
    struct buffer *buf = (struct buffer *)buffer;
    // free rqueue
    rqueue_set_free_value_callback(buf->rq, page_destroy);
    rqueue_destroy(buf->rq);
    free(buffer);
}

//TODO: unit test
int buffer_read(struct buffer *buf, void *output, int nbytes)
{
    int b_cnt = 0;

    do {
        if (buf->pg == NULL) {
            buf->pg = (struct page *)rqueue_read(buf->rq);
            //printf("pg: %p", buf->pg);
            if (buf->pg == NULL) {
                return b_cnt;
            }
            buf->offset = 0;
        }

        int can_read = (buf->pg->size) - (buf->offset);
        if (b_cnt + can_read >= nbytes) {
            // do memcpy
            memcpy(output+b_cnt, buf->pg->buf_ptr + buf->offset, nbytes-b_cnt);
            buf->offset += nbytes - b_cnt;
            b_cnt = nbytes;
            return b_cnt;
        } else {
            // read left can_read
            memcpy(output+b_cnt, buf->pg->buf_ptr + buf->offset, can_read);
            b_cnt += can_read;
            // to the next page
            page_destroy(buf->pg);
            buf->pg = NULL;
            continue;
        }

    } while(1);
}

// TODO: unit test
// return: 0 for success
// -1 for failure
// -2 for full and blocking
int buffer_write(struct buffer *buf, void *input, int nbytes)
{
    struct page *pg = page_create(input, nbytes);
    return rqueue_write(buf->rq, (void *)pg);
}

struct page *page_create(char *ptr, int size) {
    struct page *pg = NULL;
    pg = (struct page *)malloc(sizeof(struct page));
    pg->buf_ptr = (char *)malloc(sizeof(char) * size);
    pg->size = size;
    memcpy(pg->buf_ptr, ptr, size);

    return pg;
}

void page_destroy(void *page) {
    struct page *pg = (struct page *)page;
    free(pg->buf_ptr);
    free(page);
}