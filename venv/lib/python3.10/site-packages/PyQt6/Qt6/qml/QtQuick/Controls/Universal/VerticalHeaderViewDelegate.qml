// Copyright (C) 2025 The Qt Company Ltd.
// SPDX-License-Identifier: LicenseRef-Qt-Commercial OR LGPL-3.0-only OR GPL-2.0-only OR GPL-3.0-only
// Qt-Security score:significant reason:default

import QtQuick
import QtQuick.Controls.impl as ControlsImpl
import QtQuick.Controls.Universal
import QtQuick.Templates as T

T.HeaderViewDelegate {
    id: control

    // same as AbstractButton.qml
    implicitWidth: Math.max(implicitBackgroundWidth + leftInset + rightInset,
                            implicitContentWidth + leftPadding + rightPadding)
    implicitHeight: Math.max(implicitBackgroundHeight + topInset + bottomInset,
                             implicitContentHeight + topPadding + bottomPadding)

    padding: 8

    highlighted: selected

    background: Rectangle {
        implicitWidth: Math.max(control.headerView.width,
                                control.contentItem.implicitWidth
                                + (control.padding * 2))
        implicitHeight: control.contentItem.implicitHeight + (control.padding * 2)
        color: control.Universal.background
    }

    contentItem: Label {
        width: control.width
        height: control.height
        horizontalAlignment: Text.AlignHCenter
        verticalAlignment: Text.AlignVCenter
        color: ControlsImpl.Color.transparent(control.Universal.foreground,
                                              enabled ? 1.0 : 0.2)
        text: control.model[control.headerView.textRole]
    }
}
