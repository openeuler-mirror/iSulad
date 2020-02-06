# -*- coding: utf-8 -*-
'''
Description: header class and functions
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
#
#!/usr/bin/python -Es
import helpers

def append_header_arr(obj, header, prefix):
    '''
    Description: Write c header file of array
    Interface: None
    History: 2019-06-17
    '''
    if not obj.subtypobj or obj.subtypname:
        return
    header.write("typedef struct {\n")
    for i in obj.subtypobj:
        if i.typ == 'array':
            c_typ = helpers.get_prefixe_pointer(i.name, i.subtyp, prefix) or \
                helpers.get_map_c_types(i.subtyp)
            if i.subtypobj is not None:
                c_typ = helpers.get_name_substr(i.name, prefix)

            if not helpers.judge_complex(i.subtyp):
                header.write("    %s%s*%s;\n" % (c_typ, " " if '*' not in c_typ else "", \
                    i.fixname))
            else:
                header.write("    %s **%s;\n" % (c_typ, i.fixname))
            header.write("    size_t %s;\n\n" % (i.fixname + "_len"))
        else:
            c_typ = helpers.get_prefixe_pointer(i.name, i.typ, prefix) or \
                helpers.get_map_c_types(i.typ)
            header.write("    %s%s%s;\n" % (c_typ, " " if '*' not in c_typ else "", i.fixname))
    typename = helpers.get_name_substr(obj.name, prefix)
    header.write("}\n%s;\n\n" % typename)
    header.write("void free_%s(%s *ptr);\n\n" % (typename, typename))
    header.write("%s *make_%s(yajl_val tree, const struct parser_context *ctx, parser_error *err);"\
        "\n\n" % (typename, typename))


def append_header_map_str_obj(obj, header, prefix):
    '''
    Description: Write c header file of mapStringObject
    Interface: None
    History: 2019-06-17
    '''
    child = obj.children[0]
    header.write("typedef struct {\n")
    header.write("    char **keys;\n")
    if helpers.valid_basic_map_name(child.typ):
        c_typ = helpers.get_prefixe_pointer("", child.typ, "")
    elif child.subtypname:
        c_typ = child.subtypname
    else:
        c_typ = helpers.get_prefixe_pointer(child.name, child.typ, prefix)
    header.write("    %s%s*%s;\n" % (c_typ, " " if '*' not in c_typ else "", child.fixname))
    header.write("    size_t len;\n")


def append_header_child_arr(child, header, prefix):
    '''
    Description: Write c header file of array of child
    Interface: None
    History: 2019-06-17
    '''
    if helpers.get_map_c_types(child.subtyp) != "":
        c_typ = helpers.get_map_c_types(child.subtyp)
    elif helpers.valid_basic_map_name(child.subtyp):
        c_typ = '%s *' % helpers.make_basic_map_name(child.subtyp)
    elif child.subtypname is not None:
        c_typ = child.subtypname
    elif child.subtypobj is not None:
        c_typ = helpers.get_name_substr(child.name, prefix)
    else:
        c_typ = helpers.get_prefixe_pointer(child.name, child.subtyp, prefix)

    if helpers.valid_basic_map_name(child.subtyp):
        header.write("    %s **%s;\n" % (helpers.make_basic_map_name(child.subtyp), child.fixname))
    elif not helpers.judge_complex(child.subtyp):
        header.write("    %s%s*%s;\n" % (c_typ, " " if '*' not in c_typ else "", child.fixname))
    else:
        header.write("    %s%s**%s;\n" % (c_typ, " " if '*' not in c_typ else "", child.fixname))
    header.write("    size_t %s;\n\n" % (child.fixname + "_len"))


def append_header_child_others(child, header, prefix):
    '''
    Description: Write c header file of others of child
    Interface: None
    History: 2019-06-17
    '''
    if helpers.get_map_c_types(child.typ) != "":
        c_typ = helpers.get_map_c_types(child.typ)
    elif helpers.valid_basic_map_name(child.typ):
        c_typ = '%s *' % helpers.make_basic_map_name(child.typ)
    elif child.subtypname:
        c_typ = helpers.get_prefixe_pointer(child.subtypname, child.typ, "")
    else:
        c_typ = helpers.get_prefixe_pointer(child.name, child.typ, prefix)
    header.write("    %s%s%s;\n\n" % (c_typ, " " if '*' not in c_typ else "", child.fixname))


def append_type_c_header(obj, header, prefix):
    '''
    Description: Write c header file
    Interface: None
    History: 2019-06-17
    '''
    if not helpers.judge_complex(obj.typ):
        return

    if obj.typ == 'array':
        append_header_arr(obj, header, prefix)
        return

    if obj.typ == 'mapStringObject':
        if obj.subtypname is not None:
            return
        append_header_map_str_obj(obj, header, prefix)
    elif obj.typ == 'object':
        if obj.subtypname is not None:
            return
        header.write("typedef struct {\n")
        if obj.children is None:
            header.write("    char unuseful; // unuseful definition to avoid empty struct\n")
        for i in obj.children or []:
            if i.typ == 'array':
                append_header_child_arr(i, header, prefix)
            else:
                append_header_child_others(i, header, prefix)

    typename = helpers.get_prefixe_name(obj.name, prefix)
    header.write("}\n%s;\n\n" % typename)
    header.write("void free_%s(%s *ptr);\n\n" % (typename, typename))
    header.write("%s *make_%s(yajl_val tree, const struct parser_context *ctx, parser_error *err)"\
        ";\n\n" % (typename, typename))
    header.write("yajl_gen_status gen_%s(yajl_gen g, const %s *ptr, const struct parser_context "\
        "*ctx, parser_error *err);\n\n" % (typename, typename))


def header_reflect(structs, schema_info, header):
    '''
    Description: Reflection header files
    Interface: None
    History: 2019-06-17
    '''
    prefix = schema_info.prefix
    header.write("// Generated from %s. Do not edit!\n" % (schema_info.name.basename))
    header.write("#ifndef %s_SCHEMA_H\n" % prefix.upper())
    header.write("#define %s_SCHEMA_H\n\n" % prefix.upper())
    header.write("#include <sys/types.h>\n")
    header.write("#include <stdint.h>\n")
    header.write("#include \"json_common.h\"\n")
    if schema_info.refs:
        for ref in schema_info.refs.keys():
            header.write("#include \"%s\"\n" % (ref))
    header.write("\n#ifdef __cplusplus\n")
    header.write("extern \"C\" {\n")
    header.write("#endif\n\n")

    for i in structs:
        append_type_c_header(i, header, prefix)
    length = len(structs)
    toptype = structs[length - 1].typ if length != 0 else ""
    if toptype == 'object':
        header.write("%s *%s_parse_file(const char *filename, const struct parser_context *ctx, "\
            "parser_error *err);\n\n" % (prefix, prefix))
        header.write("%s *%s_parse_file_stream(FILE *stream, const struct parser_context *ctx, "\
            "parser_error *err);\n\n" % (prefix, prefix))
        header.write("%s *%s_parse_data(const char *jsondata, const struct parser_context *ctx, "\
            "parser_error *err);\n\n" % (prefix, prefix))
        header.write("char *%s_generate_json(const %s *ptr, const struct parser_context *ctx, "\
            "parser_error *err);\n\n" % (prefix, prefix))
    elif toptype == 'array':
        header.write("void free_%s(%s_element **ptr, size_t len);\n\n" % (prefix, prefix))
        header.write("%s_element **%s_parse_file(const char *filename, const struct "\
            "parser_context *ctx, parser_error *err, size_t *len);\n\n" % (prefix, prefix))
        header.write("%s_element **%s_parse_file_stream(FILE *stream, const struct "\
            "parser_context *ctx, parser_error *err, size_t *len);\n\n" % (prefix, prefix))
        header.write("%s_element **%s_parse_data(const char *jsondata, const struct "\
            "parser_context *ctx, parser_error *err, size_t *len);\n\n" % (prefix, prefix))
        header.write("char *%s_generate_json(const %s_element **ptr, size_t len, "\
            "const struct parser_context *ctx, parser_error *err);\n\n" % (prefix, prefix))

    header.write("#ifdef __cplusplus\n")
    header.write("}\n")
    header.write("#endif\n\n")
    header.write("#endif\n\n")

