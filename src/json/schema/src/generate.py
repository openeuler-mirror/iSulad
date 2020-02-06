# -*- coding: utf-8 -*-
'''
Description: header class and functions
Interface: None
History: 2019-06-17
'''

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

import traceback
import os
import sys
import json
import fcntl
import argparse

from collections import OrderedDict
import helpers
import headers
import sources
import common_h
import common_c

# - json suffix
JSON_SUFFIX = ".json"

'''
Description: ref suffix
Interface: ref_suffix
History: 2019-06-17
'''
# - Description: ref suffix
REF_SUFFIX = "_json"

'''
Description: root paths
Interface: rootpaths
History: 2019-06-17
'''
class MyRoot(object):
    '''
    Description: Store schema information
    Interface: None
    History: 2019-06-17
    '''
    def __init__(self, root_path):
        self.root_path = root_path

    def get_repr(self):
        '''
        Description: Store schema information
        Interface: None
        History: 2019-06-17
        '''
        return "{root_path:(%s)}" % (self.root_path)

    def get_path(self):
        '''
        Description: Store schema information
        Interface: None
        History: 2019-06-17
        '''
        return self.root_path


def trim_json_suffix(name):
    """
    Description: generate c language for parse json map string object
    Interface: None
    History: 2019-06-17
    """
    if name.endswith(JSON_SUFFIX) or name.endswith(REF_SUFFIX):
        name = name[:-len(JSON_SUFFIX)]
    return helpers.conv_to_c_style(name.replace('.', '_').replace('-', '_'))


def get_prefix_package(filepath, rootpath):
    """
    Description: generate c language for parse json map string object
    Interface: None
    History: 2019-06-17
    """
    realpath = os.path.realpath(filepath)

    if realpath.startswith(rootpath) and len(realpath) > len(rootpath):
        return helpers.conv_to_c_style(os.path.dirname(realpath)[(len(rootpath) + 1):])
    else:
        raise RuntimeError('schema path \"%s\" is not in scope of root path \"%s\"' \
                           % (realpath, rootpath))


def get_prefix_from_file(filepath):
    """
    Description: generate c language for parse json map string object
    Interface: None
    History: 2019-06-17
    """
    prefix_file = trim_json_suffix(os.path.basename(filepath))
    root_path = MyRoot.root_path
    prefix_package = get_prefix_package(filepath, root_path)
    prefix = prefix_file if prefix_package == "" else prefix_package + "_" + prefix_file
    return prefix


def schema_from_file(filepath, srcpath):
    """
    Description: generate c language for parse json map string object
    Interface: None
    History: 2019-06-17
    """
    schemapath = helpers.FilePath(filepath)
    prefix = get_prefix_from_file(schemapath.name)
    header = helpers.FilePath(os.path.join(srcpath, prefix + ".h"))
    source = helpers.FilePath(os.path.join(srcpath, prefix + ".c"))
    schema_info = helpers.SchemaInfo(schemapath, header, source, prefix, srcpath)
    return schema_info


def make_ref_name(refname, reffile):
    """
    Description: generate c language for parse json map string object
    Interface: None
    History: 2019-06-17
    """
    prefix = get_prefix_from_file(reffile)
    if refname == "" or prefix.endswith(refname):
        return prefix
    return prefix + "_" + helpers.conv_to_c_style(refname)


def splite_ref_name(ref):
    """
    Description: generate c language for parse json map string object
    Interface: None
    History: 2019-06-17
    """
    tmp_f, tmp_r = ref.split("#/") if '#/' in ref else (ref, "")
    return tmp_f, tmp_r


def merge(children):
    """
    Description: generate c language for parse json map string object
    Interface: None
    History: 2019-06-17
    """
    subchildren = []
    for i in children:
        for j in i.children:
            subchildren.append(j)

    return subchildren

# BASIC_TYPES include all basic types
BASIC_TYPES = (
    "byte", "int8", "int16", "int32", "int64", "uint8", "uint16", "uint32", "uint64", "UID", "GID",
    "bytePointer", "doublePointer", "int8Pointer", "int16Pointer", "int32Pointer", "int64Pointer",
    "uint8Pointer", "uint16Pointer", "uint32Pointer", "uint64Pointer", "ArrayOfStrings",
    "booleanPointer"
)


def judge_support_type(typ):
    """
    Description: generate c language for parse json map string object
    Interface: None
    History: 2019-06-17
    """
    return typ in ("integer", "boolean", "string", "double") or typ in BASIC_TYPES


def get_ref_subref(src, subref):
    """
    Description: generate c language for parse json map string object
    Interface: None
    History: 2019-06-17
    """
    cur = src
    subrefname = ""
    for j in subref.split('/'):
        subrefname = j
        if j in BASIC_TYPES:
            return src, {"type": j}, subrefname
        cur = cur[j]

    return src, cur, subrefname


def get_ref_root(schema_info, src, ref, curfile):
    """
    Description: generate c language for parse json map string object
    Interface: None
    History: 2019-06-17
    """
    refname = ""
    tmp_f, tmp_r = splite_ref_name(ref)

    if tmp_f == "":
        cur = src
    else:
        realpath = os.path.realpath(os.path.join(os.path.dirname(curfile), tmp_f))
        curfile = realpath

        subschema = schema_from_file(realpath, schema_info.filesdir)
        if schema_info.refs is None:
            schema_info.refs = {}
        schema_info.refs[subschema.header.basename] = subschema
        with open(realpath) as i:
            cur = src = json.loads(i.read())
    subcur = cur
    if tmp_r != "":
        src, subcur, refname = get_ref_subref(src, tmp_r)

    if 'type' not in subcur and '$ref' in subcur:
        subf, subr = splite_ref_name(subcur['$ref'])
        if subf == "":
            src, subcur, refname = get_ref_subref(src, subr)
            if 'type' not in subcur:
                raise RuntimeError("Not support reference of nesting more than 2 level: ", ref)
        else:
            return get_ref_root(schema_info, src, subcur['$ref'], curfile)
    return src, subcur, curfile, make_ref_name(refname, curfile)


def get_type_pattern_incur(cur, schema_info, src, curfile):
    """
    Description: generate c language for parse json map string object
    Interface: None
    History: 2019-06-17
    """
    # pattern of key:
    # '.{1,}' represents type 'string',
    # '.{2,}' represents type 'integer'
    if '.{2,}' in cur['patternProperties']:
        map_key = 'Int'
    else:
        map_key = 'String'
    for i, value in enumerate(cur['patternProperties'].values()):
        # only use the first value
        if i == 0:
            if 'type' in value:
                val = value["type"]
            else:
                dummy_subsrc, subcur, dummy_subcurfile, dummy_subrefname = get_ref_root(
                    schema_info, src, value['$ref'], curfile)
                val = subcur['type']
            break

    m_key = {
        'object': 'Object',
        'string': 'String',
        'integer': 'Int',
        'boolean': 'Bool'
    }[val]
    map_val = m_key

    typ = 'map' + map_key + map_val
    return typ


class GenerateNodeInfo(object):
    '''
    Description: Store schema information
    Interface: None
    History: 2019-06-17
    '''
    def __init__(self, schema_info, name, cur, curfile):
        self.schema_info = schema_info
        self.name = name
        self.cur = cur
        self.curfile = curfile

    def get_repr(self):
        '''
        Description: Store schema information
        Interface: None
        History: 2019-06-17
        '''
        return "{schema_info:(%s) name:(%s) cur:(%s) curfile:(%s)}" \
            % (self.schema_info, self.name, self.cur, self.curfile)

    def get_name(self):
        '''
        Description: Store schema information
        Interface: None
        History: 2019-06-17
        '''
        return self.name


def gen_all_arr_typnode(node_info, src, typ, refname):
    """
    Description: generate c language for parse json map string object
    Interface: None
    History: 2019-06-17
    """
    schema_info = node_info.schema_info
    name = node_info.name
    cur = node_info.cur
    curfile = node_info.curfile
    subtyp = None
    subtypobj = None
    required = None
    children = merge(resolve_list(schema_info, name, src, cur["items"]['allOf'], curfile))
    subtyp = children[0].typ
    subtypobj = children
    return helpers.Unite(name,
                        typ,
                        children,
                        subtyp=subtyp,
                        subtypobj=subtypobj,
                        subtypname=refname,
                        required=required), src


def gen_any_arr_typnode(node_info, src, typ, refname):
    """
    Description: generate c language for parse json map string object
    Interface: None
    History: 2019-06-17
    """
    schema_info = node_info.schema_info
    name = node_info.name
    cur = node_info.cur
    curfile = node_info.curfile
    subtyp = None
    subtypobj = None
    required = None
    anychildren = resolve_list(schema_info, name, src, cur["items"]['anyOf'], curfile)
    subtyp = anychildren[0].typ
    children = anychildren[0].children
    subtypobj = children
    refname = anychildren[0].subtypname
    return helpers.Unite(name,
                        typ,
                        children,
                        subtyp=subtyp,
                        subtypobj=subtypobj,
                        subtypname=refname,
                        required=required), src


def gen_ref_arr_typnode(node_info, src, typ, refname):
    """
    Description: generate c language for parse json map string object
    Interface: None
    History: 2019-06-17
    """
    schema_info = node_info.schema_info
    name = node_info.name
    cur = node_info.cur
    curfile = node_info.curfile

    item_type, src = resolve_type(schema_info, name, src, cur["items"], curfile)
    ref_file, subref = splite_ref_name(cur['items']['$ref'])
    if ref_file == "":
        src, dummy_subcur, subrefname = get_ref_subref(src, subref)
        refname = make_ref_name(subrefname, curfile)
    else:
        refname = item_type.subtypname
    return helpers.Unite(name,
                        typ,
                        None,
                        subtyp=item_type.typ,
                        subtypobj=item_type.children,
                        subtypname=refname,
                        required=item_type.required), src


def gen_type_arr_typnode(node_info, src, typ, refname):
    """
    Description: generate c language for parse json map string object
    Interface: None
    History: 2019-06-17
    """
    schema_info = node_info.schema_info
    name = node_info.name
    cur = node_info.cur
    curfile = node_info.curfile

    item_type, src = resolve_type(schema_info, name, src, cur["items"], curfile)
    return helpers.Unite(name,
                        typ,
                        None,
                        subtyp=item_type.typ,
                        subtypobj=item_type.children,
                        subtypname=refname,
                        required=item_type.required), src


def gen_arr_typnode(node_info, src, typ, refname):
    """
    Description: generate c language for parse json map string object
    Interface: None
    History: 2019-06-17
    """
    cur = node_info.cur

    if 'allOf' in cur["items"]:
        return gen_all_arr_typnode(node_info, src, typ, refname)
    elif 'anyOf' in cur["items"]:
        return gen_any_arr_typnode(node_info, src, typ, refname)
    elif '$ref' in cur["items"]:
        return gen_ref_arr_typnode(node_info, src, typ, refname)
    elif 'type' in cur["items"]:
        return gen_type_arr_typnode(node_info, src, typ, refname)
    return None


def gen_obj_typnode(node_info, src, typ, refname):
    """
    Description: generate c language for parse json map string object
    Interface: None
    History: 2019-06-17
    """
    schema_info = node_info.schema_info
    name = node_info.name
    cur = node_info.cur
    curfile = node_info.curfile
    children = None
    subtyp = None
    subtypobj = None
    required = None

    if 'allOf' in cur:
        children = merge(resolve_list(schema_info, name, src, cur['allOf'], curfile))
    elif 'anyOf' in cur:
        children = resolve_list(schema_info, name, src, cur['anyOf'], curfile)
    elif 'patternProperties' in cur:
        children = parse_properties(schema_info, name, src, cur, curfile)
        children[0].name = children[0].name.replace('_{1,}', 'element').replace('_{2,}', \
                                                                                'element')
        children[0].fixname = "values"
        if helpers.valid_basic_map_name(children[0].typ):
            children[0].name = helpers.make_basic_map_name(children[0].typ)
    else:
        children = parse_properties(schema_info, name, src, cur, curfile) \
            if 'properties' in cur else None
    if 'required' in cur:
        required = cur['required']
    return helpers.Unite(name,\
            typ,\
            children,\
            subtyp=subtyp,\
            subtypobj=subtypobj,\
            subtypname=refname,\
            required=required), src


def get_typ_notoneof(schema_info, src, cur, curfile):
    """
    Description: generate c language for parse json map string object
    Interface: None
    History: 2019-06-17
    """
    if 'patternProperties' in cur:
        typ = get_type_pattern_incur(cur, schema_info, src, curfile)
    elif "type" in cur:
        typ = cur["type"]
    else:
        typ = "object"

    return typ


def resolve_type(schema_info, name, src, cur, curfile):
    """
    Description: generate c language for parse json map string object
    Interface: None
    History: 2019-06-17
    """
    children = None
    subtyp = None
    subtypobj = None
    required = None
    refname = None

    if '$ref' in cur:
        src, cur, curfile, refname = get_ref_root(schema_info, src, cur['$ref'], curfile)

    if "oneOf" in cur:
        cur = cur['oneOf'][0]
        if '$ref' in cur:
            return resolve_type(schema_info, name, src, cur, curfile)
        else:
            typ = cur['type']
    else:
        typ = get_typ_notoneof(schema_info, src, cur, curfile)

    node_info = GenerateNodeInfo(schema_info, name, cur, curfile)

    if helpers.valid_basic_map_name(typ):
        pass
    elif typ == 'array':
        return gen_arr_typnode(node_info, src, typ, refname)
    elif typ == 'object' or typ == 'mapStringObject':
        return gen_obj_typnode(node_info, src, typ, refname)
    elif typ == 'ArrayOfStrings':
        typ = 'array'
        subtyp = 'string'
        children = subtypobj = None
    else:
        if not judge_support_type(typ):
            raise RuntimeError("Invalid schema type: %s" % typ)
        children = None

    return helpers.Unite(name,
                        typ,
                        children,
                        subtyp=subtyp,
                        subtypobj=subtypobj,
                        subtypname=refname,
                        required=required), src


def resolve_list(schema_info, name, schema, objs, curfile):
    """
    Description: generate c language for parse json map string object
    Interface: None
    History: 2019-06-17
    """
    obj = []
    index = 0
    for i in objs:
        generated_name = helpers.CombinateName( \
            i['$ref'].split("/")[-1]) if '$ref' in i \
            else helpers.CombinateName(name.name + str(index))
        node, _ = resolve_type(schema_info, generated_name, schema, i, curfile)
        if node:
            obj.append(node)
        index += 1
    if not obj:
        obj = None
    return obj


def parse_dict(schema_info, name, schema, objs, curfile):
    """
    Description: generate c language for parse json map string object
    Interface: None
    History: 2019-06-17
    """
    obj = []
    for i in objs:
        node, _ = resolve_type(schema_info, name.append(i), schema, objs[i], curfile)
        if node:
            obj.append(node)
    if not obj:
        obj = None
    return obj


def parse_properties(schema_info, name, schema, props, curfile):
    """
    Description: generate c language for parse json map string object
    Interface: None
    History: 2019-06-17
    """
    if 'definitions' in props:
        return parse_dict(schema_info, name, schema, props['definitions'], curfile)
    if 'patternProperties' in props:
        return parse_dict(schema_info, name, schema, props['patternProperties'], curfile)
    return parse_dict(schema_info, name, schema, props['properties'], curfile)


def handle_type_not_in_schema(schema_info, schema, prefix):
    """
    Description: generate c language for parse json map string object
    Interface: None
    History: 2019-06-17
    """
    required = None
    if 'definitions' in schema:
        return helpers.Unite( \
            helpers.CombinateName("definitions"), 'definitions', \
            parse_properties(schema_info, helpers.CombinateName(""), schema, schema, \
                            schema_info.name.name), None, None, None, None)
    else:
        if len(schema) > 1:
            print('More than one element found in schema')
            return None
        value_nodes = []
        for value in schema:
            if 'required' in schema[value]:
                required = schema[value]['required']
            childrens = parse_properties(schema_info, helpers.CombinateName(""), \
                                        schema[value], schema[value], \
                                        schema_info.name.name)
            value_node = helpers.Unite(helpers.CombinateName(prefix), \
                                       'object', childrens, None, None, \
                                       None, required)
            value_nodes.append(value_node)
        return helpers.Unite(helpers.CombinateName("definitions"), \
                             'definitions', value_nodes, None, None, \
                            None, None)


def parse_schema(schema_info, schema, prefix):
    """
    Description: generate c language for parse json map string object
    Interface: None
    History: 2019-06-17
    """
    required = None
    if 'type' not in schema:
        return handle_type_not_in_schema(schema_info, schema, prefix)

    if 'object' in schema['type']:
        if 'required' in schema:
            required = schema['required']
        return helpers.Unite(
            helpers.CombinateName(prefix), 'object',
            parse_properties(schema_info, \
                            helpers.CombinateName(""), \
                            schema, schema, schema_info.name.name), \
            None, None, None, required)
    elif 'array' in schema['type']:
        item_type, _ = resolve_type(schema_info, helpers.CombinateName(""), \
                                    schema['items'], schema['items'], schema_info.name.name)
        return helpers.Unite(helpers.CombinateName(prefix), 'array', None, item_type.typ, \
                            item_type.children, None, item_type.required)
    else:
        print("Not supported type '%s'") % schema['type']
    return prefix, None


def expand(tree, structs, visited):
    """
    Description: generate c language for parse json map string object
    Interface: None
    History: 2019-06-17
    """
    if tree.children is not None:
        for i in tree.children:
            if tree.subtypname:
                i.subtypname = "from_ref"
            expand(i, structs, visited=visited)
    if tree.subtypobj is not None:
        for i in tree.subtypobj:
            expand(i, structs, visited=visited)

    if tree.typ == 'array' and helpers.valid_basic_map_name(tree.subtyp):
        name = helpers.CombinateName(tree.name + "_element")
        node = helpers.Unite(name, tree.subtyp, None)
        expand(node, structs, visited)

    id_ = "%s:%s" % (tree.name, tree.typ)
    if id_ not in visited.keys():
        structs.append(tree)
        visited[id_] = tree

    return structs


def reflection(schema_info, gen_ref):
    """
    Description: generate c language for parse json map string object
    Interface: None
    History: 2019-06-17
    """
    with open(schema_info.header.name, "w") as \
            header_file, open(schema_info.source.name, "w") as source_file:
        fcntl.flock(header_file, fcntl.LOCK_EX)
        fcntl.flock(source_file, fcntl.LOCK_EX)

        with open(schema_info.name.name) as schema_file:
            schema_json = json.loads(schema_file.read(), object_pairs_hook=OrderedDict)
            try:
                tree = parse_schema(schema_info, schema_json, schema_info.prefix)
                if tree is None:
                    print("Failed parse schema")
                    sys.exit(1)
                structs = expand(tree, [], {})
                headers.header_reflect(structs, schema_info, header_file)
                sources.src_reflect(structs, schema_info, source_file, tree.typ)
            except RuntimeError:
                traceback.print_exc()
                print("Failed to parse schema file: %s") % schema_info.name.name
                sys.exit(1)
            finally:
                pass

        fcntl.flock(source_file, fcntl.LOCK_UN)
        fcntl.flock(header_file, fcntl.LOCK_UN)

    if gen_ref is True:
        if schema_info.refs:
            for reffile in schema_info.refs.values():
                reflection(reffile, True)


def gen_common_files(out):
    """
    Description: generate c language for parse json map string object
    Interface: None
    History: 2019-06-17
    """
    print(out, "  gao\n")
    with open(os.path.join(out, 'json_common.h'), "w") as \
            header_file, open(os.path.join(out, 'json_common.c'), "w") as source_file:
        fcntl.flock(header_file, fcntl.LOCK_EX)
        fcntl.flock(source_file, fcntl.LOCK_EX)

        header_file.write(common_h.CODE)
        source_file.write(common_c.CODE)

        fcntl.flock(source_file, fcntl.LOCK_UN)
        fcntl.flock(header_file, fcntl.LOCK_UN)


def handle_single_file(args, srcpath, gen_ref, schemapath):
    """
    Description: generate c language for parse json map string object
    Interface: None
    History: 2019-06-17
    """
    if not os.path.exists(schemapath.name) or not os.path.exists(srcpath.name):
        print('Path %s is not exist') % schemapath.name
        sys.exit(1)

    if os.path.isdir(schemapath.name):
        if args.recursive is True:
            # recursively parse schema
            for dirpath, dummy_dirnames, files in os.walk(schemapath.name):
                for target_file in files:
                    if target_file.endswith(JSON_SUFFIX):
                        schema_info = schema_from_file(os.path.join(dirpath, target_file), \
                                                       srcpath.name)
                        reflection(schema_info, gen_ref)
        else:
            # only parse files in current direcotory
            for target_file in os.listdir(schemapath.name):
                fullpath = os.path.join(schemapath.name, target_file)
                if fullpath.endswith(JSON_SUFFIX) and os.path.isfile(fullpath):
                    schema_info = schema_from_file(fullpath, srcpath.name)
                    reflection(schema_info, gen_ref)
    else:
        if schemapath.name.endswith(JSON_SUFFIX):
            schema_info = schema_from_file(schemapath.name, srcpath.name)
            reflection(schema_info, gen_ref)
        else:
            print('File %s is not ends with .json') % schemapath.name


def handle_files(args, srcpath):
    """
    Description: generate c language for parse json map string object
    Interface: None
    History: 2019-06-17
    """
    for path in args.path:
        gen_ref = args.gen_ref
        schemapath = helpers.FilePath(path)
        handle_single_file(args, srcpath, gen_ref, schemapath)


def main():
    """
    Description: generate c language for parse json map string object
    Interface: None
    History: 2019-06-17
    """
    parser = argparse.ArgumentParser(prog='generate.py',
                                     usage='%(prog)s [options] path [path ...]',
                                     description='Generate C header and source from json-schema')
    parser.add_argument('path', nargs='+', help='File or directory to parse')
    parser.add_argument(
        '--root',
        required=True,
        help=
        'All schema files must be placed in root directory or sub-directory of root," \
        " and naming of C variables is started from this path'
    )
    parser.add_argument('--gen-common',
                        action='store_true',
                        help='Generate json_common.c and json_common.h')
    parser.add_argument('--gen-ref',
                        action='store_true',
                        help='Generate reference file defined in schema with key \"$ref\"')
    parser.add_argument('-r',
                        '--recursive',
                        action='store_true',
                        help='Recursively generate all schema files in directory')
    parser.add_argument(
        '--out',
        help='Specify a directory to save C header and source(default is current directory)')
    args = parser.parse_args()

    if not args.root:
        print('Missing root path, see help')
        sys.exit(1)

    root_path = os.path.realpath(args.root)
    if not os.path.exists(root_path):
        print('Root %s is not exist') % args.root
        sys.exit(1)

    MyRoot.root_path = root_path

    if args.out:
        srcpath = helpers.FilePath(args.out)
    else:
        srcpath = helpers.FilePath(os.getcwd())
    if not os.path.exists(srcpath.name):
        os.makedirs(srcpath.name)

    if args.gen_common:
        gen_common_files(srcpath.name)
    handle_files(args, srcpath)


if __name__ == "__main__":
    main()


