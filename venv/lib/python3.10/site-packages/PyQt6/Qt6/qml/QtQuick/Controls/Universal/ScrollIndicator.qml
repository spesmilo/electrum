// Copyright (C) 2017 The Qt Company Ltd.
// SPDX-License-Identifier: LicenseRef-Qt-Commercial OR LGPL-3.0-only OR GPL-2.0-only OR GPL-3.0-only
// Qt-Security score:significant reason:default

import QtQuick
import QtQuick.Templates as T
import QtQuick.Controls.Universal

T.ScrollIndicator {
    id: control

    implicitWidth: Math.max(implicitBackgroundWidth + leftInset + rightInset,
                            implicitContentWidth + leftPadding + rightPadding)
    implicitHeight: Math.max(implicitBackgroundHeight + topInset + bottomInset,
                             implicitContentHeight + topPadding + bottomPadding)

    contentItem: Rectangle {
        implicitWidth: 6
        implicitHeight: 6

        color: control.Universal.baseMediumLowColor
        visible: control.size < 1.0
        opacity: 0.0

        states: [
            State {
                name: "active"
                when: control.active
            }
        ]

        transitions: [
            Transition {
                to: "active"
                NumberAnimation { target: control.contentItem; property: "opacity"; to: 1.0 }
            },
            Transition {
                from: "active"
                SequentialAnimation {
                    PauseAnimation { duration: 5000 }
                    NumberAnimation { target: control.contentItem; property: "opacity"; to: 0.0 }
                }
            }
        ]
    }
}
