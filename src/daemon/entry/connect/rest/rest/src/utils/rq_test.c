#include <pthread.h>
#include "buffer_rqueue.h"
#include "string.h"
#include <stdio.h>
#include <unistd.h>

#define NUM 10
#define NBYTES 500
#define OUT    250

static struct buffer *buf;


void *write_thread(void *ptr)
{
    int i;
    int ret; 
    char input[NBYTES];
    printf("here\n");
    for (i = 0; i < NUM; i++) {
        int num = '0' + rand()%10;
        int nbytes = rand() % 500;
        memset(input, num, NBYTES);
        if ((ret = buffer_write(buf, input, nbytes)) == -1) {
            printf("error occured");
            break;
        } else if (ret == -2) {
            printf("full");
            //sleep for a while? retry 
        }
    }
}

void *read_thread(void *ptr)
{
    char output[OUT];
    int ret;
    int cnt = 0; 
    while (cnt < NUM) {
        ret = buffer_read(buf, output, OUT);
        printf("read %d bytes", ret);
        if (ret == 0) {
            sleep(1);
        }
        for (int i = 0; i < ret; i++) {
            putc(output[i], stdout);
        }
        printf("\n");
        cnt++;
    }
}

void *test_thread(void *ptr)
{
    printf("hello\n");
}

int main(void)
{
    buf = buffer_create(512, RQUEUE_MODE_BLOCKING);
    pthread_t reader;
    pthread_t writer;

    //write_thread(NULL);
    //printf("%s", rqueue_stats(buf->rq));
    //read_thread(NULL);
    pthread_create(&writer, NULL, write_thread, NULL);
    pthread_create(&reader, NULL, read_thread, NULL);


    // sleep(1000);
    pthread_join(reader, NULL);
    pthread_join(writer, NULL);
    // sleep(1000);
    buffer_destroy((void *)buf);
    return 0;
}