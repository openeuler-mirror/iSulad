# -*- coding: utf-8 -*-
'''
Description: commom header file
Interface: None
History: 2019-06-17
'''
#
# libocispec - a C library for parsing OCI spec files.
#
# Copyright (C) 2017, 2019 Giuseppe Scrivano <giuseppe@scrivano.org>
# Copyright (C) Huawei Technologies., Ltd. 2018-2019. All rights reserved.
#
# libocispec is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 3 of the License, or
# (at your option) any later version.
#
# libocispec is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with libocispec.  If not, see <http://www.gnu.org/licenses/>.
#
# As a special exception, you may create a larger work that contains
# part or all of the libocispec parser skeleton and distribute that work
# under terms of your choice, so long as that work isn't itself a
# parser generator using the skeleton or a modified version thereof
# as a parser skeleton.  Alternatively, if you modify or redistribute
# the parser skeleton itself, you may (at your option) remove this
# special exception, which will cause the skeleton and the resulting
# libocispec output files to be licensed under the GNU General Public
# License without this special exception.
#!/usr/bin/python -Es

"""
Description: json common c code
Interface: None
History: 2019-06-18
Purpose: defined the common tool function for parse json
Defined the CODE global variable to hold the c code
"""
# - Defined the CODE global variable to hold the c code
CODE = '''// Auto generated file. Do not edit!
# ifndef _JSON_COMMON_H
# define _JSON_COMMON_H

# include <stdlib.h>
# include <stdbool.h>
# include <stdio.h>
# include <string.h>
# include <stdint.h>
# include <yajl/yajl_tree.h>
# include <yajl/yajl_gen.h>

# ifdef __cplusplus
extern "C" {
# endif

# undef linux

// options to report error if there is unknown key found in json
# define OPT_PARSE_STRICT 0x01
// options to generate all key and value
# define OPT_GEN_KAY_VALUE 0x02
// options to generate simplify(no indent) json string
# define OPT_GEN_SIMPLIFY 0x04
// options not to validate utf8 data
# define OPT_GEN_NO_VALIDATE_UTF8 0x08

# define GEN_SET_ERROR_AND_RETURN(stat, err) { \\
    if (*(err) == NULL) {\\
        if (asprintf(err, "%s: %s: %d: error generating json, errcode: %u", __FILE__, __func__, __LINE__, stat) < 0) { \\
            *(err) = safe_strdup("error allocating memory"); \\
        } \\
    }\\
    return stat; \\
}

typedef char *parser_error;

struct parser_context {
    unsigned int options;
    FILE *stderr;
};

yajl_gen_status map_uint(void *ctx, long long unsigned int num);

yajl_gen_status map_int(void *ctx, long long int num);

bool json_gen_init(yajl_gen *g, const struct parser_context *ctx);

yajl_val get_val(yajl_val tree, const char *name, yajl_type type);

void *safe_malloc(size_t size);

int common_safe_double(const char *numstr, double *converted);

int common_safe_uint8(const char *numstr, uint8_t *converted);

int common_safe_uint16(const char *numstr, uint16_t *converted);

int common_safe_uint32(const char *numstr, uint32_t *converted);

int common_safe_uint64(const char *numstr, uint64_t *converted);

int common_safe_uint(const char *numstr, unsigned int *converted);

int common_safe_int8(const char *numstr, int8_t *converted);

int common_safe_int16(const char *numstr, int16_t *converted);

int common_safe_int32(const char *numstr, int32_t *converted);

int common_safe_int64(const char *numstr, int64_t *converted);

int common_safe_int(const char *numstr, int *converted);

char *safe_strdup(const char *src);

typedef struct {
    int *keys;
    int *values;
    size_t len;
} json_map_int_int;

void free_json_map_int_int(json_map_int_int *map);

json_map_int_int *make_json_map_int_int(yajl_val src, const struct parser_context *ctx, parser_error *err);

yajl_gen_status gen_json_map_int_int(void *ctx, const json_map_int_int *map, const struct parser_context *ptx, parser_error *err);

int append_json_map_int_int(json_map_int_int *map, int key, int val);

typedef struct {
    int *keys;
    bool *values;
    size_t len;
} json_map_int_bool;

void free_json_map_int_bool(json_map_int_bool *map);

json_map_int_bool *make_json_map_int_bool(yajl_val src, const struct parser_context *ctx, parser_error *err);

yajl_gen_status gen_json_map_int_bool(void *ctx, const json_map_int_bool *map, const struct parser_context *ptx, parser_error *err);

int append_json_map_int_bool(json_map_int_bool *map, int key, bool val);

typedef struct {
    int *keys;
    char **values;
    size_t len;
} json_map_int_string;

void free_json_map_int_string(json_map_int_string *map);

json_map_int_string *make_json_map_int_string(yajl_val src, const struct parser_context *ctx, parser_error *err);

yajl_gen_status gen_json_map_int_string(void *ctx, const json_map_int_string *map, const struct parser_context *ptx, parser_error *err);

int append_json_map_int_string(json_map_int_string *map, int key, const char *val);

typedef struct {
    char **keys;
    int *values;
    size_t len;
} json_map_string_int;

void free_json_map_string_int(json_map_string_int *map);

json_map_string_int *make_json_map_string_int(yajl_val src, const struct parser_context *ctx, parser_error *err);

yajl_gen_status gen_json_map_string_int(void *ctx, const json_map_string_int *map, const struct parser_context *ptx, parser_error *err);

int append_json_map_string_int(json_map_string_int *map, const char *key, int val);

typedef struct {
    char **keys;
    bool *values;
    size_t len;
} json_map_string_bool;

void free_json_map_string_bool(json_map_string_bool *map);

json_map_string_bool *make_json_map_string_bool(yajl_val src, const struct parser_context *ctx, parser_error *err);

yajl_gen_status gen_json_map_string_bool(void *ctx, const json_map_string_bool *map, const struct parser_context *ptx, parser_error *err);

int append_json_map_string_bool(json_map_string_bool *map, const char *key, bool val);

typedef struct {
    char **keys;
    char **values;
    size_t len;
} json_map_string_string;

void free_json_map_string_string(json_map_string_string *map);

json_map_string_string *make_json_map_string_string(yajl_val src, const struct parser_context *ctx, parser_error *err);

yajl_gen_status gen_json_map_string_string(void *ctx, const json_map_string_string *map, const struct parser_context *ptx, parser_error *err);

int append_json_map_string_string(json_map_string_string *map, const char *key, const char *val);

char *json_marshal_string(const char *str, size_t strlen, const struct parser_context *ctx, parser_error *err);

# ifdef __cplusplus
}
# endif

# endif
'''
