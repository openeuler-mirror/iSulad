/******************************************************************************
 * Copyright (c) China Unicom Technologies Co., Ltd. 2023. All rights reserved.
 * iSulad licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *     http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
 * Author: Chenwei
 * Create: 2023-08-25
 * Description: print progress
 ******************************************************************************/

#include "show.h"
#include <sys/ioctl.h>
#include <stdio.h>
#include <term.h>
#include <unistd.h>

void move_to_row(int row)
{
    printf("\033[%d;1H", row);
    fflush(stdout);
}

void move_cursor_up(int rows)
{
    printf("\033[%dA", rows);  // ANSI escape code to move cursor up 'rows' rows
}

void clear_row(int row)
{
    move_to_row(row);
    printf("\033[2K");
    fflush(stdout);
}

void clear_lines_below()
{
    printf("\x1b[J");  // ANSI escape code to clear from cursor to end of screen
    fflush(stdout);
}

int get_current_row()
{
    struct termios term;
    if (tcgetattr(STDOUT_FILENO, &term) == -1) {
        perror("tcgetattr");
        return -1;
    }
    return term.c_cc[VERASE];
}

int get_terminal_width()
{
    struct winsize ws;
    if (ioctl(STDOUT_FILENO, TIOCGWINSZ, &ws) == -1) {
        perror("ioctl");
        return -1; // Error
    }
    return ws.ws_col;
}
