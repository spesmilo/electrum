// Copyright (C) 2017 The Qt Company Ltd.
// SPDX-License-Identifier: LicenseRef-Qt-Commercial OR LGPL-3.0-only OR GPL-2.0-only OR GPL-3.0-only
// Qt-Security score:significant reason:default

import QtQuick
import QtQuick.Templates as T
import QtQuick.Controls.impl
import QtQuick.Controls.Universal

T.SpinBox {
    id: control


    // Note: the width of the indicators are calculated into the padding
    implicitWidth: Math.max(implicitBackgroundWidth + leftInset + rightInset,
                            contentItem.implicitWidth + leftPadding + rightPadding)
    implicitHeight: Math.max(implicitBackgroundHeight + topInset + bottomInset,
                             implicitContentHeight + topPadding + bottomPadding,
                             up.implicitIndicatorHeight, down.implicitIndicatorHeight)

    // TextControlThemePadding + 2 (border)
    padding: 12
    topPadding: padding - 7
    leftPadding: padding + (control.mirrored ? (up.indicator ? up.indicator.width : 0) : (down.indicator ? down.indicator.width : 0))
    rightPadding: padding + (control.mirrored ? (down.indicator ? down.indicator.width : 0) : (up.indicator ? up.indicator.width : 0))
    bottomPadding: padding - 5

    Universal.theme: activeFocus ? Universal.Light : undefined

    validator: IntValidator {
        locale: control.locale.name
        bottom: Math.min(control.from, control.to)
        top: Math.max(control.from, control.to)
    }

    contentItem: TextInput {
        text: control.displayText

        font: control.font
        color: !enabled ? control.Universal.chromeDisabledLowColor :
                activeFocus ? control.Universal.chromeBlackHighColor : control.Universal.foreground
        selectionColor: control.Universal.accent
        selectedTextColor: control.Universal.chromeWhiteColor
        horizontalAlignment: Qt.AlignHCenter
        verticalAlignment: TextInput.AlignVCenter

        readOnly: !control.editable
        validator: control.validator
        inputMethodHints: control.inputMethodHints
        clip: width < implicitWidth
    }

    up.indicator: Item {
        implicitWidth: 28
        height: control.height + 4
        y: -2
        x: control.mirrored ? 0 : control.width - width

        Rectangle {
            x: 2; y: 4
            width: parent.width - 4
            height: parent.height - 8
            color: control.activeFocus ? control.Universal.accent :
                   control.up.pressed ? control.Universal.baseMediumLowColor :
                   control.up.hovered ? control.Universal.baseLowColor : "transparent"
            visible: control.up.pressed || control.up.hovered
            opacity: control.activeFocus && !control.up.pressed ? 0.4 : 1.0
        }

        ColorImage {
            x: (parent.width - width) / 2
            y: (parent.height - height) / 2
            color: !enabled ? control.Universal.chromeDisabledLowColor :
                              control.activeFocus ? control.Universal.chromeBlackHighColor : control.Universal.baseHighColor
            source: "qrc:/qt-project.org/imports/QtQuick/Controls/Universal/images/" + (control.mirrored ? "left" : "right") + "arrow.png"
        }
    }

    down.indicator: Item {
        implicitWidth: 28
        height: control.height + 4
        y: -2
        x: control.mirrored ? control.width - width : 0

        Rectangle {
            x: 2; y: 4
            width: parent.width - 4
            height: parent.height - 8
            color: control.activeFocus ? control.Universal.accent :
                   control.down.pressed ? control.Universal.baseMediumLowColor :
                   control.down.hovered ? control.Universal.baseLowColor : "transparent"
            visible: control.down.pressed || control.down.hovered
            opacity: control.activeFocus && !control.down.pressed ? 0.4 : 1.0
        }

        ColorImage {
            x: (parent.width - width) / 2
            y: (parent.height - height) / 2
            color: !enabled ? control.Universal.chromeDisabledLowColor :
                              control.activeFocus ? control.Universal.chromeBlackHighColor : control.Universal.baseHighColor
            source: "qrc:/qt-project.org/imports/QtQuick/Controls/Universal/images/" + (control.mirrored ? "right" : "left") + "arrow.png"
        }
    }

    background: Rectangle {
        implicitWidth: 60 + 28 // TextControlThemeMinWidth - 4 (border)
        implicitHeight: 28 // TextControlThemeMinHeight - 4 (border)

        border.width: 2 // TextControlBorderThemeThickness
        border.color: !control.enabled ? control.Universal.baseLowColor :
                       control.activeFocus ? control.Universal.accent :
                       control.hovered ? control.Universal.baseMediumColor : control.Universal.chromeDisabledLowColor
        color: control.enabled ? control.Universal.background : control.Universal.baseLowColor
    }
}
