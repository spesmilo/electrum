// Copyright (C) 2017 The Qt Company Ltd.
// SPDX-License-Identifier: LicenseRef-Qt-Commercial OR LGPL-3.0-only OR GPL-2.0-only OR GPL-3.0-only
// Qt-Security score:significant reason:default

import QtQuick
import QtQuick.Controls.impl
import QtQuick.Templates as T

T.DelayButton {
    id: control

    implicitWidth: Math.max(implicitBackgroundWidth + leftInset + rightInset,
                            implicitContentWidth + leftPadding + rightPadding)
    implicitHeight: Math.max(implicitBackgroundHeight + topInset + bottomInset,
                             implicitContentHeight + topPadding + bottomPadding)

    padding: 6
    horizontalPadding: padding + 2

    transition: Transition {
        NumberAnimation {
            duration: control.delay * (control.pressed ? 1.0 - control.progress : 0.3 * control.progress)
        }
    }

    contentItem: ItemGroup {
        ClippedText {
            clip: control.progress > 0
            clipX: -control.leftPadding + control.progress * control.width
            clipWidth: (1.0 - control.progress) * control.width
            visible: control.progress < 1

            text: control.text
            font: control.font
            opacity: enabled ? 1 : 0.3
            color: control.palette.buttonText
            horizontalAlignment: Text.AlignHCenter
            verticalAlignment: Text.AlignVCenter
            elide: Text.ElideRight
        }

        ClippedText {
            clip: control.progress > 0
            clipX: -control.leftPadding
            clipWidth: control.progress * control.width
            visible: control.progress > 0

            text: control.text
            font: control.font
            opacity: enabled ? 1 : 0.3
            color: control.palette.brightText
            horizontalAlignment: Text.AlignHCenter
            verticalAlignment: Text.AlignVCenter
            elide: Text.ElideRight
        }
    }

    background: Rectangle {
        implicitWidth: 100
        implicitHeight: 40
        color: Color.blend(control.palette.button, control.palette.mid, control.down ? 0.5 : 0.0)
        border.color: control.visualFocus ? control.palette.highlight : control.palette.windowText
        border.width: control.visualFocus ? 2 :
                      Qt.styleHints.accessibility.contrastPreference === Qt.HighContrast ? 1 : 0

        PaddedRectangle {
            padding: control.visualFocus ? 2 : 0
            width: control.progress * parent.width
            height: parent.height
            color: Color.blend(control.palette.dark, control.palette.mid, control.down ? 0.5 : 0.0)
        }
    }
}
