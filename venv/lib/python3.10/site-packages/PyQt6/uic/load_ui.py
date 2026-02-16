# Copyright (c) 2020 Riverbank Computing Limited.
# Copyright (c) 2006 Thorsten Marek.
# All right reserved.
#
# This file is part of PyQt.
#
# You may use this file under the terms of the GPL v3 or the revised BSD
# license as follows:
#
# "Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are
# met:
#   * Redistributions of source code must retain the above copyright
#     notice, this list of conditions and the following disclaimer.
#   * Redistributions in binary form must reproduce the above copyright
#     notice, this list of conditions and the following disclaimer in
#     the documentation and/or other materials provided with the
#     distribution.
#   * Neither the name of the Riverbank Computing Limited nor the names
#     of its contributors may be used to endorse or promote products
#     derived from this software without specific prior written
#     permission.
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
# OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE."


def loadUiType(uifile):
    """loadUiType(uifile) -> (form class, base class)

    Load a Qt Designer .ui file and return the generated form class and the Qt
    base class.

    uifile is a file name or file-like object containing the .ui file.
    """

    import io
    import sys

    from PyQt6 import QtWidgets

    from .Compiler import compiler

    code_string = io.StringIO()
    winfo = compiler.UICompiler().compileUi(uifile, code_string)

    ui_globals = {}
    exec(code_string.getvalue(), ui_globals)

    uiclass = winfo["uiclass"]
    baseclass = winfo["baseclass"]

    # Assume that the base class is a custom class exposed in the globals.
    ui_base = ui_globals.get(baseclass)
    if ui_base is None:
        # Otherwise assume it is in the QtWidgets module.
        ui_base = getattr(QtWidgets, baseclass)

    return (ui_globals[uiclass], ui_base)


def loadUi(uifile, baseinstance=None, package=''):
    """loadUi(uifile, baseinstance=None, package='') -> widget

    Load a Qt Designer .ui file and return an instance of the user interface.

    uifile is a file name or file-like object containing the .ui file.
    baseinstance is an optional instance of the Qt base class.  If specified
    then the user interface is created in it.  Otherwise a new instance of the
    base class is automatically created.
    package is the optional package which is used as the base for any relative
    imports of custom widgets.
    """

    from .Loader.loader import DynamicUILoader

    return DynamicUILoader(package).loadUi(uifile, baseinstance)
