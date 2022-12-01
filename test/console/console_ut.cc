#include <sys/stat.h>
#include <gtest/gtest.h>
#include <fcntl.h>
#include <limits.h>
#include <string.h>

#include "console.h"

#define FIFO_NAME "fifo1"
#define PATH_NOT_EXIST "./path_not_found/"
#define LONGER_PATH_MAX 4098

TEST(utils_console, test_console_fifo_create)
{
    int ret = 0;
    struct stat buf;

    ret = console_fifo_create(FIFO_NAME);
    if (ret != 0) {
        return;
    }

    if (stat(FIFO_NAME, &buf) < 0) {
        return;
    }

    ASSERT_EQ(S_ISFIFO(buf.st_mode), true);

    ret = access(FIFO_NAME, R_OK|W_OK);
    ASSERT_EQ(ret, 0);

    remove(FIFO_NAME);
}

TEST(utils_console, test_console_fifo_create_failed)
{
    int ret = 0;

    ret = console_fifo_create(PATH_NOT_EXIST FIFO_NAME);
    ASSERT_EQ(ret, -1);
}

TEST(utils_console, test_console_fifo_delete)
{
    int ret = 0;
    char path_buf[LONGER_PATH_MAX] = { 0x00 };

    memset(path_buf, 'a', LONGER_PATH_MAX);
    path_buf[LONGER_PATH_MAX - 1] = 0;
    ASSERT_EQ(strlen(path_buf), LONGER_PATH_MAX-1)<< "strlen is " << strlen(path_buf);

    ret = console_fifo_create(FIFO_NAME);
    if (ret != 0) {
        return;
    }

    // PATH TOO LONG
    ret = console_fifo_delete(path_buf);
    ASSERT_EQ(ret, -1) << []()->std::string { remove(FIFO_NAME); return "failed"; }();

    // PATH NULL
    ret = console_fifo_delete(NULL);
    ASSERT_EQ(ret, -1) << []()->std::string { remove(FIFO_NAME); return "failed"; }();

    // PATH LEN IS ZERO
    ret = console_fifo_delete("");
    ASSERT_EQ(ret, 0) << []()->std::string { remove(FIFO_NAME); return "failed"; }();

    // PATH NOT FOUND
    ret = console_fifo_delete(PATH_NOT_EXIST FIFO_NAME);
    ASSERT_EQ(ret, 0) << []()->std::string { remove(FIFO_NAME); return "failed"; }();

    ret = console_fifo_delete(FIFO_NAME);
    ASSERT_EQ(ret, 0) << []()->std::string { remove(FIFO_NAME); return "failed"; }();
}

TEST(utils_console, test_console_fifo_open)
{
    int ret = 0;
    int fifooutfd = -1;

    ret = console_fifo_create(FIFO_NAME);
    if (ret != 0) {
        return;
    }

    ret = console_fifo_open(FIFO_NAME, &fifooutfd, O_RDWR | O_NONBLOCK);
    ASSERT_EQ(ret, 0) << []()->std::string { remove(FIFO_NAME); return "failed"; }();
    console_fifo_close(fifooutfd);
    remove(FIFO_NAME);
}

TEST(utils_console, test_console_fifo_open_withlock)
{
    int ret = 0;
    int fifooutfd = -1;

    ret = console_fifo_create(FIFO_NAME);
    if (ret != 0) {
        return;
    }

    ret = console_fifo_open_withlock(FIFO_NAME, &fifooutfd, O_RDWR | O_NONBLOCK);
    ASSERT_EQ(ret, 0) << []()->std::string { remove(FIFO_NAME); return "failed"; }();
    console_fifo_close(fifooutfd);
    remove(FIFO_NAME);
}
