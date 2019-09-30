# -*- coding: utf-8 -*-
'''
Description: helper class and functions
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
import os
import sys

def appendSeparator(subStr):
    '''
    Description: append only '_' at last position of subStr
    Interface: None
    History: 2019-09-20
    '''
    if subStr and subStr[-1] != '_':
        subStr.append('_')

def convertToCStyle(name):
    '''
    Description: convert name to linux c format
    Interface: None
    History: 2019-06-17
    '''
    if name is None or name == "":
        return ""
    name = name.replace('.', '_').replace('-', '_').replace('/', '_')
    subStr = []
    preindex = 0
    index = 0
    for index, char in enumerate(name):
        if char == '_':
            appendSeparator(subStr)
            subStr.append(name[preindex:index].lower())
            preindex = index + 1
        if not char.isupper() and name[preindex].isupper() and \
                name[preindex + 1].isupper():
            appendSeparator(subStr)
            subStr.append(name[preindex:index - 1].lower())
            preindex = index - 1
            continue
        if char.isupper() and index > 0 and name[index - 1].islower():
            appendSeparator(subStr)
            subStr.append(name[preindex:index].lower())
            preindex = index

    if preindex <= index and index >= 0 and name[index] != '_' and \
            preindex != 0:
        appendSeparator(subStr)
    subStr.append(name[preindex:index + 1].lower())
    result = ''.join(subStr)
    return result

def getMapCTypes(typ):
    '''
    Description: Get map c types
    Interface: None
    History: 2019-06-17
    '''
    map_c_types = {
        'byte': 'uint8_t',
        'string': 'char *',
        'integer': 'int',
        'boolean': 'bool',
        'double': 'double',
        'int8': 'int8_t',
        "int16": 'int16_t',
        "int32": "int32_t",
        "int64": "int64_t",
        'uint8': 'uint8_t',
        "uint16": 'uint16_t',
        "uint32": "uint32_t",
        "uint64": "uint64_t",
        "UID": "uid_t",
        "GID": "gid_t",
        "booleanPointer": "bool *",
        'bytePointer': 'uint8_t *',
        'integerPointer': 'int *',
        'doublePointer': 'double *',
        'int8Pointer': 'int8_t *',
        "int16Pointer": 'int16_t *',
        "int32Pointer": "int32_t *",
        "int64Pointer": "int64_t *",
        'uint8Pointer': 'uint8_t *',
        "uint16Pointer": 'uint16_t *',
        "uint32Pointer": "uint32_t *",
        "uint64Pointer": "uint64_t *",
    }
    if typ in map_c_types:
        return map_c_types[typ]
    return ""

def validBasicMapName(typ):
    '''
    Description: Valid basic map name
    Interface: None
    History: 2019-06-17
    '''
    return typ != 'mapStringObject' and hasattr(typ, 'startswith') and \
        typ.startswith('map')

def makeBasicMapName(mapname):
    '''
    Description: Make basic map name
    Interface: None
    History: 2019-06-17
    '''
    basic_map_types = ('string', 'int', 'bool')
    parts = convertToCStyle(mapname).split('_')
    if len(parts) != 3 or parts[0] != 'map' or \
            (parts[1] not in basic_map_types) or \
            (parts[2] not in basic_map_types):
        print('Invalid map name: %s') % mapname
        sys.exit(1)
    return "json_map_%s_%s" % (parts[1], parts[2])


def getNameSubstr(name, prefix):
    '''
    Description: Make array name
    Interface: None
    History: 2019-06-17
    '''
    return "%s_element" % prefix if name is None or name == "" or prefix == name \
        else "%s_%s_element" % (prefix, name)

def getPrefixName(name, prefix):
    '''
    Description: Make name
    Interface: None
    History: 2019-06-17
    '''
    if name is None or name == "" or prefix.endswith(name):
        return "%s" % prefix
    if prefix is None or prefix == "" or prefix == name or name.endswith(prefix):
        return "%s" % name
    return "%s_%s" % (prefix, name)

def getPrefixPointer(name, typ, prefix):
    '''
    Description: Make pointer name
    Interface: None
    History: 2019-06-17
    '''
    if typ != 'object' and typ != 'mapStringObject' and \
            not validBasicMapName(typ):
        return ""
    return '%s *' % makeBasicMapName(typ) if validBasicMapName(typ) \
        else "%s *" % getPrefixName(name, prefix)

def judgeComplex(typ):
    '''
    Description: Check compound object
    Interface: None
    History: 2019-06-17
    '''
    return typ in ('object', 'array', 'mapStringObject')

def judgeDataType(typ):
    '''
    Description: Check numeric type
    Interface: None
    History: 2019-06-17
    '''
    if (typ.startswith("int") or typ.startswith("uint")) and \
            "Pointer" not in typ:
        return True
    return typ in ("integer", "UID", "GID", "double")

def judgeDataPointerType(typ):
    '''
    Description: Check numeric pointer type
    Interface: None
    History: 2019-06-17
    '''
    if (typ.startswith("int") or typ.startswith("uint")) and "Pointer" in typ:
        return True
    return False

def obtainDataPointerType(typ):
    '''
    Description: Get numeric pointer type
    Interface: None
    History: 2019-06-17
    '''
    index = typ.find("Pointer")
    return typ[0:index] if index != -1 else ""

def obtainPointer(name, typ, prefix):
    '''
    Description: Obtain pointer string
    Interface: None
    History: 2019-06-17
    '''
    ptr = getPrefixPointer(name, typ, prefix)
    if ptr != "":
        return ptr

    return "char *" if typ == "string" else \
        ("%s *" % typ if typ == "ArrayOfStrings" else "")

class CombinationName(object):
    '''
    Description: Store CombinationName information
    Interface: None
    History: 2019-06-17
    '''

    def __init__(self, name, leaf=None):
        self.name = name
        self.leaf = leaf

    def __repr__(self):
        return self.name

    def __str__(self):
        return self.name

    def append(self, leaf):
        '''
        Description: append name
        Interface: None
        History: 2019-06-17
        '''
        prefix_name = self.name + '_' if self.name != "" else ""
        return CombinationName(prefix_name + leaf, leaf)


class Unite(object):
    '''
    Description: Store Unite information
    Interface: None
    History: 2019-06-17
    '''
    def __init__(self, name, typ, children, subtyp=None, subtypobj=None, subtypname=None, \
        required=None):
        self.typ = typ
        self.children = children
        self.subtyp = subtyp
        self.subtypobj = subtypobj
        self.subtypname = subtypname
        self.required = required
        self.name = convertToCStyle(name.name.replace('.', '_'))
        self.origname = name.leaf or name.name
        self.fixname = convertToCStyle(self.origname.replace('.', '_'))



    def __repr__(self):
        if self.subtyp is not None:
            return "name:(%s) type:(%s -> %s)" \
                % (self.name, self.typ, self.subtyp)
        return "name:(%s) type:(%s)" % (self.name, self.typ)

    def __str__(self):
        return self.__repr__(self)


class FilePath(object):
    '''
    Description: Store filepath information
    Interface: None
    History: 2019-06-17
    '''
    def __init__(self, name):
        self.name = os.path.realpath(name)
        self.dirname = os.path.dirname(self.name)
        self.basename = os.path.basename(self.name)

    def __repr__(self):
        return "{name:(%s) dirname:(%s) basename:(%s)}" \
            % (self.name, self.dirname, self.basename)

    def __str__(self):
        return self.__repr__(self)


class SchemaInfo(object):
    '''
    Description: Store schema information
    Interface: None
    History: 2019-06-17
    '''

    def __init__(self, name, header, source, prefix, filesdir, refs=None):
        self.name = name
        self.fileprefix = convertToCStyle( \
            name.basename.replace('.', '_').replace('-', '_'))
        self.header = header
        self.source = source
        self.prefix = prefix
        self.refs = refs
        self.filesdir = os.path.realpath(filesdir)

    def __repr__(self):
        return "{name:(%s) header:(%s) source:(%s) prefix:(%s)}" \
            % (self.name, self.header, self.source, self.prefix)

    def __str__(self):
        return self.__repr__(self)
