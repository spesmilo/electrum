// Copyright (C) 2024 The Qt Company Ltd.
// SPDX-License-Identifier: LicenseRef-Qt-Commercial OR LGPL-3.0-only OR GPL-2.0-only OR GPL-3.0-only
// Qt-Security score:significant reason:default

import QtQuick
import QtQuick.Templates as T
import QtQuick.Shapes

T.BusyIndicator {
    id: control

    implicitWidth: Math.max(implicitBackgroundWidth + leftInset + rightInset,
                            implicitContentWidth + leftPadding + rightPadding)
    implicitHeight: Math.max(implicitBackgroundHeight + topInset + bottomInset,
                             implicitContentHeight + topPadding + bottomPadding)

    contentItem: Item {
        implicitWidth: 32
        implicitHeight: 32
        x: (control.availableWidth - width) / 2
        y: (control.availableHeight - height) / 2

        property Shape ring: Shape {
            parent: control.contentItem
            x: (parent.width - width) / 2
            y: (parent.height - height) / 2
            implicitWidth: parent.implicitWidth
            implicitHeight: parent.implicitHeight
            width: Math.min(control.contentItem.width, control.contentItem.height)
            height: width
            preferredRendererType: Shape.CurveRenderer
            antialiasing: true

            ShapePath {
                fillColor: "transparent"
                strokeColor: control.palette.accent
                strokeWidth: control.contentItem.ring.width >= 64 ? 6 : control.contentItem.ring.width <= 16 ? 1 : 3

                capStyle: ShapePath.RoundCap

                PathAngleArc {
                    centerX: control.contentItem.ring.width / 2
                    centerY: control.contentItem.ring.height / 2
                    radiusX: control.contentItem.ring.width / 2 - 2
                    radiusY: radiusX
                    startAngle: -90
                    sweepAngle: 120

                    SequentialAnimation on startAngle {
                        loops: Animation.Infinite
                        running: control.visible && control.running
                        NumberAnimation { from: 0; to: 450; duration: 1000 }
                        NumberAnimation { from: 450; to: 1080; duration: 1000 }
                    }

                    SequentialAnimation on sweepAngle {
                        loops: Animation.Infinite
                        running: control.visible && control.running
                        NumberAnimation { from: 0; to: 180; duration: 1000 }
                        NumberAnimation { from: 180; to: 0; duration: 1000 }
                    }
                }
            }
        }
    }
}
