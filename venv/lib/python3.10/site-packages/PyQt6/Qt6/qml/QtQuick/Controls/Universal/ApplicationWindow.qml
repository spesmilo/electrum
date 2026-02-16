// Copyright (C) 2017 The Qt Company Ltd.
// SPDX-License-Identifier: LicenseRef-Qt-Commercial OR LGPL-3.0-only OR GPL-2.0-only OR GPL-3.0-only
// Qt-Security score:significant reason:default

import QtQuick
import QtQuick.Window
import QtQuick.Templates as T
import QtQuick.Controls.Universal
import QtQuick.Controls.Universal.impl

T.ApplicationWindow {
    id: window

    color: Universal.background

    FocusRectangle {
        parent: window.activeFocusControl
        width: parent ? parent.width : 0
        height: parent ? parent.height : 0
        visible: parent && !!parent.useSystemFocusVisuals && !!parent.visualFocus
    }
}
