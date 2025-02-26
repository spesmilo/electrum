# JSON serialization support for Google's protobuf Messages
# Copyright (c) 2009, Paul Dovbush
# All rights reserved.
# http://code.google.com/p/protobuf-json/
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are
# met:
#
#     * Redistributions of source code must retain the above copyright
# notice, this list of conditions and the following disclaimer.
#     * Redistributions in binary form must reproduce the above
# copyright notice, this list of conditions and the following disclaimer
# in the documentation and/or other materials provided with the
# distribution.
#     * Neither the name of <ORGANIZATION> nor the names of its
# contributors may be used to endorse or promote products derived from
# this software without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
# "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
# LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
# A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
# OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
# SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
# LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
# DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
# THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
# (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
# OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

'''
Provide serialization and de-serialization of Google's protobuf Messages into/from JSON format.
'''

# groups are deprecated and not supported;
# Note that preservation of unknown fields is currently not available for Python (c) google docs
# extensions is not supported from 0.0.5 (due to gpb2.3 changes)

__version__='0.0.5'
__author__='Paul Dovbush <dpp@dpp.su>'


import json
from google.protobuf.descriptor import FieldDescriptor as FD
import binascii
import types_pb2 as types

class ParseError(Exception): pass


def json2pb(pb, js):
    ''' convert JSON string to google.protobuf.descriptor instance '''
    for field in pb.DESCRIPTOR.fields:
        if field.name not in js:
            continue
        if field.type == FD.TYPE_MESSAGE:
            pass
        elif field.type in _js2ftype:
            ftype = _js2ftype[field.type]
        else:
            raise ParseError("Field %s.%s of type '%d' is not supported" % (pb.__class__.__name__, field.name, field.type, ))
        value = js[field.name]
        if field.label == FD.LABEL_REPEATED:
            pb_value = getattr(pb, field.name, None)
            for v in value:
                if field.type == FD.TYPE_MESSAGE:
                    json2pb(pb_value.add(), v)
                else:
                    pb_value.append(ftype(v))
        else:
            if field.type == FD.TYPE_MESSAGE:
                json2pb(getattr(pb, field.name, None), value)
            else:
                setattr(pb, field.name, ftype(value))
    return pb



def pb2json(pb):
    ''' convert google.protobuf.descriptor instance to JSON string '''
    js = {}
    # fields = pb.DESCRIPTOR.fields #all fields
    fields = pb.ListFields()    #only filled (including extensions)
    for field,value in fields:
        if field.type == FD.TYPE_MESSAGE:
            ftype = pb2json
        elif field.type == FD.TYPE_ENUM:
            ftype = lambda x: field.enum_type.values[x].name
        elif field.type in _ftype2js:
            ftype = _ftype2js[field.type]
        else:
            raise ParseError("Field %s.%s of type '%d' is not supported" % (pb.__class__.__name__, field.name, field.type, ))
        if field.label == FD.LABEL_REPEATED:
            js_value = []
            for v in value:
                js_value.append(ftype(v))
        else:
            js_value = ftype(value)
        js[field.name] = js_value
    return js


_ftype2js = {
    FD.TYPE_DOUBLE: float,
    FD.TYPE_FLOAT: float,
    FD.TYPE_INT64: long,
    FD.TYPE_UINT64: long,
    FD.TYPE_INT32: int,
    FD.TYPE_FIXED64: float,
    FD.TYPE_FIXED32: float,
    FD.TYPE_BOOL: bool,
    FD.TYPE_STRING: unicode,
    #FD.TYPE_MESSAGE handled specially
    FD.TYPE_BYTES: lambda x: binascii.hexlify(x),
    FD.TYPE_UINT32: int,
    # FD.TYPE_ENUM: handled specially
    FD.TYPE_SFIXED32: float,
    FD.TYPE_SFIXED64: float,
    FD.TYPE_SINT32: int,
    FD.TYPE_SINT64: long,
}

_js2ftype = {
    FD.TYPE_DOUBLE: float,
    FD.TYPE_FLOAT: float,
    FD.TYPE_INT64: long,
    FD.TYPE_UINT64: long,
    FD.TYPE_INT32: int,
    FD.TYPE_FIXED64: float,
    FD.TYPE_FIXED32: float,
    FD.TYPE_BOOL: bool,
    FD.TYPE_STRING: unicode,
    # FD.TYPE_MESSAGE handled specially
    FD.TYPE_BYTES: lambda x: binascii.unhexlify(x),
    FD.TYPE_UINT32: int,
    FD.TYPE_ENUM: lambda x: getattr(types, x),
    FD.TYPE_SFIXED32: float,
    FD.TYPE_SFIXED64: float,
    FD.TYPE_SINT32: int,
    FD.TYPE_SINT64: long,
}
