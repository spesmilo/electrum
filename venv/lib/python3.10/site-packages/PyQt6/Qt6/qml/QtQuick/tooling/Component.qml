// Copyright (C) 2020 The Qt Company Ltd.
// SPDX-License-Identifier: LicenseRef-Qt-Commercial OR LGPL-3.0-only OR GPL-2.0-only OR GPL-3.0-only

import QML
import QtQuick.tooling as Tooling

QtObject {
    default property list<Tooling.Member> members

    property string file
    property int lineNumber
    required property string name
    property list<string> aliases: []
    property string prototype
    property list<string> exports: []
    property list<int> exportMetaObjectRevisions
    property list<string> interfaces
    property list<string> deferredNames
    property list<string> immediateNames
    property string attachedType
    property string valueType
    property string extension
    property bool isSingleton: false
    property bool isCreatable: accessSemantics === "reference" && name.length > 0
    property bool isStructured: false
    property bool isComposite: false
    property bool isJavaScriptBuiltin: false
    property bool hasCustomParser: false
    property bool extensionIsJavaScript: false
    property bool extensionIsNamespace: false
    property bool enforcesScopedEnums: false
    property string accessSemantics: "reference"
    property string defaultProperty
    property string parentProperty
}
