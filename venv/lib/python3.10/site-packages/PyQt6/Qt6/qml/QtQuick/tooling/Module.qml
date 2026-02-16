// Copyright (C) 2020 The Qt Company Ltd.
// SPDX-License-Identifier: LicenseRef-Qt-Commercial OR LGPL-3.0-only OR GPL-2.0-only OR GPL-3.0-only

import QML
import QtQuick.tooling as Tooling

QtObject {
    default property list<Tooling.Component> components
    property list<string> dependencies: []
}
