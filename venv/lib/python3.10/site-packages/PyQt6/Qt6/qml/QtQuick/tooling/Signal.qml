// Copyright (C) 2020 The Qt Company Ltd.
// SPDX-License-Identifier: LicenseRef-Qt-Commercial OR LGPL-3.0-only OR GPL-2.0-only OR GPL-3.0-only

import QML
import QtQuick.tooling as Tooling

Tooling.Member {
    default property list<Tooling.Parameter> parameters
    property int revision: 0
    property string type
    property bool isCloned: false
    property bool isMethodConstant: false
}
