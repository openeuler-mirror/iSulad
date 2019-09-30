# -*- coding: utf-8 -*-
'''
Description: header class and functions
Interface: None
History: 2019-06-17
'''
# - Copyright (C) Huawei Technologies., Ltd. 2018-2019. All rights reserved.
# - iSulad licensed under the Mulan PSL v1.
# - You can use this software according to the terms and conditions of the Mulan PSL v1.
# - You may obtain a copy of Mulan PSL v1 at:
# -     http://license.coscl.org.cn/MulanPSL
# - THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
# - IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
# - PURPOSE.
# - See the Mulan PSL v1 for more details.
# - Description: generate json
# - Author: tanyifeng
# - Create: 2018-04-25
#!/usr/bin/python -Es
import helpers

def appendHeaderArray(obj, header, prefix):
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
            c_typ = helpers.getPrefixPointer(i.name, i.subtyp, prefix) or \
                helpers.getMapCTypes(i.subtyp)
            if i.subtypobj is not None:
                c_typ = helpers.getNameSubstr(i.name, prefix)

            if not helpers.judgeComplex(i.subtyp):
                header.write("    %s%s*%s;\n" % (c_typ, " " if '*' not in c_typ else "", \
                    i.fixname))
            else:
                header.write("    %s **%s;\n" % (c_typ, i.fixname))
            header.write("    size_t %s;\n\n" % (i.fixname + "_len"))
        else:
            c_typ = helpers.getPrefixPointer(i.name, i.typ, prefix) or \
                helpers.getMapCTypes(i.typ)
            header.write("    %s%s%s;\n" % (c_typ, " " if '*' not in c_typ else "", i.fixname))
    typename = helpers.getNameSubstr(obj.name, prefix)
    header.write("}\n%s;\n\n" % typename)
    header.write("void free_%s(%s *ptr);\n\n" % (typename, typename))
    header.write("%s *make_%s(yajl_val tree, const struct parser_context *ctx, parser_error *err);"\
        "\n\n" % (typename, typename))

def appendHeaderMapStrObj(obj, header, prefix):
    '''
    Description: Write c header file of mapStringObject
    Interface: None
    History: 2019-06-17
    '''
    child = obj.children[0]
    header.write("typedef struct {\n")
    header.write("    char **keys;\n")
    if helpers.validBasicMapName(child.typ):
        c_typ = helpers.getPrefixPointer("", child.typ, "")
    elif child.subtypname:
        c_typ = child.subtypname
    else:
        c_typ = helpers.getPrefixPointer(child.name, child.typ, prefix)
    header.write("    %s%s*%s;\n" % (c_typ, " " if '*' not in c_typ else "", child.fixname))
    header.write("    size_t len;\n")

def appendHeaderChildArray(child, header, prefix):
    '''
    Description: Write c header file of array of child
    Interface: None
    History: 2019-06-17
    '''
    if helpers.getMapCTypes(child.subtyp) != "":
        c_typ = helpers.getMapCTypes(child.subtyp)
    elif helpers.validBasicMapName(child.subtyp):
        c_typ = '%s *' % helpers.makeBasicMapName(child.subtyp)
    elif child.subtypname is not None:
        c_typ = child.subtypname
    elif child.subtypobj is not None:
        c_typ = helpers.getNameSubstr(child.name, prefix)
    else:
        c_typ = helpers.getPrefixPointer(child.name, child.subtyp, prefix)

    if helpers.validBasicMapName(child.subtyp):
        header.write("    %s **%s;\n" % (helpers.makeBasicMapName(child.subtyp), child.fixname))
    elif not helpers.judgeComplex(child.subtyp):
        header.write("    %s%s*%s;\n" % (c_typ, " " if '*' not in c_typ else "", child.fixname))
    else:
        header.write("    %s%s**%s;\n" % (c_typ, " " if '*' not in c_typ else "", child.fixname))
    header.write("    size_t %s;\n\n" % (child.fixname + "_len"))

def appendHeaderChildOthers(child, header, prefix):
    '''
    Description: Write c header file of others of child
    Interface: None
    History: 2019-06-17
    '''
    if helpers.getMapCTypes(child.typ) != "":
        c_typ = helpers.getMapCTypes(child.typ)
    elif helpers.validBasicMapName(child.typ):
        c_typ = '%s *' % helpers.makeBasicMapName(child.typ)
    elif child.subtypname:
        c_typ = helpers.getPrefixPointer(child.subtypname, child.typ, "")
    else:
        c_typ = helpers.getPrefixPointer(child.name, child.typ, prefix)
    header.write("    %s%s%s;\n\n" % (c_typ, " " if '*' not in c_typ else "", child.fixname))

def appendTypeCHeader(obj, header, prefix):
    '''
    Description: Write c header file
    Interface: None
    History: 2019-06-17
    '''
    if not helpers.judgeComplex(obj.typ):
        return

    if obj.typ == 'array':
        appendHeaderArray(obj, header, prefix)
        return

    if obj.typ == 'mapStringObject':
        if obj.subtypname is not None:
            return
        appendHeaderMapStrObj(obj, header, prefix)
    elif obj.typ == 'object':
        if obj.subtypname is not None:
            return
        header.write("typedef struct {\n")
        if obj.children is None:
            header.write("    char unuseful;//unuseful definition to avoid empty struct\n")
        for i in obj.children or [ ]:
            if i.typ == 'array':
                appendHeaderChildArray(i, header, prefix)
            else:
                appendHeaderChildOthers(i, header, prefix)

    typename = helpers.getPrefixName(obj.name, prefix)
    header.write("}\n%s;\n\n" % typename)
    header.write("void free_%s(%s *ptr);\n\n" % (typename, typename))
    header.write("%s *make_%s(yajl_val tree, const struct parser_context *ctx, parser_error *err)"\
        ";\n\n" % (typename, typename))
    header.write("yajl_gen_status gen_%s(yajl_gen g, const %s *ptr, const struct parser_context "\
        "*ctx, parser_error *err);\n\n" % (typename, typename))

def headerReflection(structs, schema_info, header):
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
        appendTypeCHeader(i, header, prefix)
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
