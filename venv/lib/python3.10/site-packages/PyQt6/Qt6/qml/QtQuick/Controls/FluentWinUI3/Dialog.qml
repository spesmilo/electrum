// Copyright (C) 2024 The Qt Company Ltd.
// SPDX-License-Identifier: LicenseRef-Qt-Commercial OR LGPL-3.0-only OR GPL-2.0-only OR GPL-3.0-only
// Qt-Security score:significant reason:default

import QtQuick
import QtQuick.Templates as T
import QtQuick.Controls.impl
import QtQuick.Effects

T.Dialog {
    id: control

    implicitWidth: Math.max(implicitBackgroundWidth + leftInset + rightInset,
                            implicitContentWidth + leftPadding + rightPadding,
                            implicitHeaderWidth,
                            implicitFooterWidth)
    implicitHeight: Math.max(implicitBackgroundHeight + topInset + bottomInset,
                             implicitContentHeight + topPadding + bottomPadding
                             + (implicitHeaderHeight > 0 ? implicitHeaderHeight + spacing : 0)
                             + (implicitFooterHeight > 0 ? implicitFooterHeight + spacing : 0))

    readonly property bool __isHighContrast: Application.styleHints.accessibility.contrastPreference === Qt.HighContrast

    leftInset: __isHighContrast ? 0 : -32
    topInset: __isHighContrast ? 0 : -32
    rightInset: __isHighContrast ? 0 : -32
    bottomInset: __isHighContrast ? 0 : -32

    padding: 24
    topPadding: 12
    bottomPadding: 23

    enter: Transition {
        NumberAnimation { property: "opacity"; from: 0.0; to: 1.0; easing.type: Easing.Linear; duration: 83 }
        NumberAnimation { property: "scale"; from: control.modal ? 1.05 : 1; to: 1; easing.type: Easing.OutCubic; duration: 167 }
    }

    exit: Transition {
        NumberAnimation { property: "opacity"; from: 1.0; to: 0.0; easing.type: Easing.Linear; duration: 83 }
        NumberAnimation { property: "scale"; from: 1; to: control.modal ? 1.05 : 1; easing.type: Easing.OutCubic; duration: 167 }
    }

    background: Rectangle {
        color: control.__isHighContrast ? control.palette.window : "transparent"
        border.color: control.__isHighContrast ? control.palette.text : "transparent"
        border.width: 2
        radius: 8
        MultiEffect {
            visible: !control.__isHighContrast
            x: -control.leftInset
            y: -control.topInset
            width: source.width
            height: source.height
            source: Rectangle {
                width: control.background.width + control.leftInset + control.rightInset
                height: control.background.height + control.topInset + control.bottomInset
                color: Application.styleHints.colorScheme === Qt.Light ? "white" : Qt.tint(control.palette.window, Color.transparent("white", 0.05))
                border.color: "#66757575"
                radius: 8
            }
            shadowScale: 1
            shadowOpacity: 0.19
            shadowColor: control.palette.shadow
            shadowEnabled: true
            shadowHorizontalOffset: 0
            shadowVerticalOffset: 32
            blurMax: 64
        }
    }

    header: Label {
        text: control.title
        topPadding: control.padding
        leftPadding: control.padding
        rightPadding: control.padding
        visible: control.title && parent?.parent === Overlay.overlay
        elide: Label.ElideRight
        font.bold: true
        font.pixelSize: 20
        font.weight: Font.DemiBold
    }

    footer: DialogButtonBox {
        visible: count > 0
        leftInset: control.__isHighContrast ? 1 : 0
        topInset: control.__isHighContrast ? 1 : 0
        rightInset: control.__isHighContrast ? 1 : 0
        bottomInset: control.__isHighContrast ? 1 : 0
    }

    T.Overlay.modal: Rectangle {
        color: Color.transparent(control.palette.shadow, 0.3)
    }

    T.Overlay.modeless: Rectangle {
        color: "transparent"
    }
}
