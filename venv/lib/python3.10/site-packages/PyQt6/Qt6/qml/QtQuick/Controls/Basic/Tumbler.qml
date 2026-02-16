// Copyright (C) 2017 The Qt Company Ltd.
// SPDX-License-Identifier: LicenseRef-Qt-Commercial OR LGPL-3.0-only OR GPL-2.0-only OR GPL-3.0-only
// Qt-Security score:significant reason:default

import QtQuick
import QtQuick.Controls.impl
import QtQuick.Templates as T

T.Tumbler {
    id: control

    implicitWidth: Math.max(implicitBackgroundWidth + leftInset + rightInset,
                            implicitContentWidth + leftPadding + rightPadding)
    implicitHeight: Math.max(implicitBackgroundHeight + topInset + bottomInset,
                             implicitContentHeight + topPadding + bottomPadding)

    readonly property real __delegateHeight: availableHeight / visibleItemCount

    delegate: Text {
        text: modelData
        color: control.visualFocus ? control.palette.highlight : control.palette.text
        font: control.font
        opacity: 1.0 - Math.abs(Tumbler.displacement) / (control.visibleItemCount / 2)
        horizontalAlignment: Text.AlignHCenter
        verticalAlignment: Text.AlignVCenter

        // We use required property here to satisfy qmllint, but that means
        // we also need to declare the index for the attached properties
        // (see QQuickTumblerAttachedPrivate::init).
        required property var modelData
        required property int index
    }

    contentItem: TumblerView {
        implicitWidth: 60
        implicitHeight: 200
        model: control.model
        delegate: control.delegate
        path: Path {
            startX: control.contentItem.width / 2
            startY: -control.__delegateHeight / 2

            PathLine {
                x: control.contentItem.width / 2
                y: (control.visibleItemCount + 1) * control.__delegateHeight - control.__delegateHeight / 2
            }
        }
    }

    background: Rectangle {
        visible: Qt.styleHints.accessibility.contrastPreference === Qt.HighContrast
        border.color: control.visualFocus ? control.palette.highlight : control.palette.windowText
        border.width: control.visualFocus ? 2 : 1
    }
}
