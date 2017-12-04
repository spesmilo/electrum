# Copyright (c) 2016, Neil Booth
#
# All rights reserved.
#
# See the file "LICENCE" for information about the copyright
# and warranty status of this software.

'''An enum-like type with reverse lookup.

Source: Python Cookbook, http://code.activestate.com/recipes/67107/
'''


class EnumError(Exception):
    pass


class Enumeration:

    def __init__(self, name, enumList):
        self.__doc__ = name

        lookup = {}
        reverseLookup = {}
        i = 0
        uniqueNames = set()
        uniqueValues = set()
        for x in enumList:
            if isinstance(x, tuple):
                x, i = x
            if not isinstance(x, str):
                raise EnumError("enum name {} not a string".format(x))
            if not isinstance(i, int):
                raise EnumError("enum value {} not an integer".format(i))
            if x in uniqueNames:
                raise EnumError("enum name {} not unique".format(x))
            if i in uniqueValues:
                raise EnumError("enum value {} not unique".format(x))
            uniqueNames.add(x)
            uniqueValues.add(i)
            lookup[x] = i
            reverseLookup[i] = x
            i = i + 1
        self.lookup = lookup
        self.reverseLookup = reverseLookup

    def __getattr__(self, attr):
        result = self.lookup.get(attr)
        if result is None:
            raise AttributeError('enumeration has no member {}'.format(attr))
        return result

    def whatis(self, value):
        return self.reverseLookup[value]
