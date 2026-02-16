// Copyright (C) 2021 The Qt Company Ltd.
// SPDX-License-Identifier: LicenseRef-Qt-Commercial OR LGPL-3.0-only OR GPL-2.0-only OR GPL-3.0-only

import QML
import QtQuick.tooling as Tooling

Tooling.Member {
    property string type
    property bool isPointer: false
    property bool isReadonly: false
    property bool isRequired: false
    property bool isList: false
    property bool isFinal: false
    property bool isTypeConstant: false
    property bool isPropertyConstant: false
    property int revision: 0
    property string bindable
    property string read
    property string write
    property string reset
    property string notify
    property string privateClass
    property int index: -1
}
