// Copyright (C) 2017 The Qt Company Ltd.
// SPDX-License-Identifier: LicenseRef-Qt-Commercial OR LGPL-3.0-only OR GPL-2.0-only OR GPL-3.0-only
// Qt-Security score:significant reason:default

import QtQuick
import QtQuick.Templates as T
import QtQuick.Controls.impl
import QtQuick.Controls.Material
import QtQuick.Controls.Material.impl

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

    // https://m3.material.io/components/dialogs/specs#7dbad5e0-f001-4eae-a536-694aeca90ba6
    padding: 24
    topPadding: 16
    // https://m3.material.io/components/dialogs/guidelines#812cedf1-5c45-453f-97fc-7fd9bba7522b
    modal: true

    // https://m3.material.io/components/dialogs/specs#401a48c3-f50c-4fa9-b798-701f5adcf155
    // Specs say level 3 (6 dp) is the default, yet the screenshots there show 0. Native Android defaults to non-zero.
    Material.elevation: 6
    Material.roundedScale: Material.dialogRoundedScale

    enter: Transition {
        // grow_fade_in
        NumberAnimation { property: "scale"; from: 0.9; to: 1.0; easing.type: Easing.OutQuint; duration: 220 }
        NumberAnimation { property: "opacity"; from: 0.0; to: 1.0; easing.type: Easing.OutCubic; duration: 150 }
    }

    exit: Transition {
        // shrink_fade_out
        NumberAnimation { property: "scale"; from: 1.0; to: 0.9; easing.type: Easing.OutQuint; duration: 220 }
        NumberAnimation { property: "opacity"; from: 1.0; to: 0.0; easing.type: Easing.OutCubic; duration: 150 }
    }

    background: Rectangle {
        // FullScale doesn't make sense for Dialog.
        radius: parent?.parent === Overlay.overlay ? control.Material.roundedScale : 0
        color: control.Material.dialogColor

        layer.enabled: control.Material.elevation > 0
        layer.effect: RoundedElevationEffect {
            elevation: control.Material.elevation
            roundedScale: control.background.radius
        }
    }

    header: Label {
        text: control.title
        visible: parent?.parent === Overlay.overlay && control.title
        elide: Label.ElideRight
        padding: 24
        bottomPadding: 0
        // TODO: QPlatformTheme::TitleBarFont
        // https://m3.material.io/components/dialogs/specs#401a48c3-f50c-4fa9-b798-701f5adcf155
        font.pixelSize: Material.dialogTitleFontPixelSize
        background: PaddedRectangle {
            radius: control.background.radius
            color: control.Material.dialogColor
            bottomPadding: -radius
            clip: true
        }
    }

    footer: DialogButtonBox {
        visible: count > 0
    }

    T.Overlay.modal: Rectangle {
        color: control.Material.backgroundDimColor
        Behavior on opacity { NumberAnimation { duration: 150 } }
    }

    T.Overlay.modeless: Rectangle {
        color: control.Material.backgroundDimColor
        Behavior on opacity { NumberAnimation { duration: 150 } }
    }
}
