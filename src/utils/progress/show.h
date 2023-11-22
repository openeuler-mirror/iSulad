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

#ifndef UTILS_SHOW_H
#define UTILS_SHOW_H

#ifdef __cplusplus
extern "C" {
#endif

void move_to_row(int row);
void move_cursor_up(int lines);
void clear_row(int row);
void clear_lines_below();
int get_current_row();
int get_terminal_width();

#ifdef __cplusplus
}
#endif

#endif
