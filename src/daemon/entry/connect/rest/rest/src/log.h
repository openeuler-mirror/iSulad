#ifndef LOG_H
#define LOG_H

#include <errno.h>
#include <stdio.h>

#define DEBUG 1
#define MAXLINE 4096

#define log_debug(fmt, ...) \
        do { if (DEBUG) fprintf(stderr, "%s:%d:%s(): " fmt "\n", __FILE__, \
                                __LINE__, __func__, ##__VA_ARGS__);} while (0)

#define log_err(fmt, ...) \
        do { fprintf(stderr, "[ERROR]%s:%d:%s(): " fmt "\n", __FILE__, \
                                __LINE__, __func__, ##__VA_ARGS__); } while (0)

#define log_sys_err(s) \
        do { perror("[SYSERR]" s); } while(0)

#define log_info(fmt, ...) \
    do { fprintf(stderr, "[INFO]" fmt "\n", ##__VA_ARGS__);} while(0)
#endif
