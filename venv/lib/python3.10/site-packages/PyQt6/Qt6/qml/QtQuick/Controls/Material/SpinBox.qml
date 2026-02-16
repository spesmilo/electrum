// Copyright (C) 2017 The Qt Company Ltd.
// SPDX-License-Identifier: LicenseRef-Qt-Commercial OR LGPL-3.0-only OR GPL-2.0-only OR GPL-3.0-only
// Qt-Security score:significant reason:default

import QtQuick
import QtQuick.Templates as T
import QtQuick.Controls.Material
import QtQuick.Controls.Material.impl

T.SpinBox {
    id: control

    // Note: the width of the indicators are calculated into the padding
    implicitWidth: Math.max(implicitBackgroundWidth + leftInset + rightInset,
                            contentItem.implicitWidth + leftPadding + rightPadding)
    implicitHeight: Math.max(implicitBackgroundHeight + topInset + bottomInset,
                             implicitContentHeight + topPadding + bottomPadding,
                             up.implicitIndicatorHeight, down.implicitIndicatorHeight)

    spacing: 6
    topPadding: Material.textFieldVerticalPadding
    bottomPadding: Material.textFieldVerticalPadding
    leftPadding: control.mirrored ? (up.indicator ? up.indicator.width : 0) : (down.indicator ? down.indicator.width : 0)
    rightPadding: control.mirrored ? (down.indicator ? down.indicator.width : 0) : (up.indicator ? up.indicator.width : 0)

    validator: IntValidator {
        locale: control.locale.name
        bottom: Math.min(control.from, control.to)
        top: Math.max(control.from, control.to)
    }

    contentItem: TextInput {
        text: control.displayText

        font: control.font
        color: enabled ? control.Material.foreground : control.Material.hintTextColor
        selectionColor: control.Material.textSelectionColor
        selectedTextColor: control.Material.foreground
        horizontalAlignment: Qt.AlignHCenter
        verticalAlignment: Qt.AlignVCenter

        cursorDelegate: CursorDelegate { }

        readOnly: !control.editable
        validator: control.validator
        inputMethodHints: control.inputMethodHints
        clip: width < implicitWidth
    }

    up.indicator: Item {
        x: control.mirrored ? 0 : control.width - width
        implicitWidth: control.Material.touchTarget
        implicitHeight: control.Material.touchTarget
        height: control.height
        width: height

        Ripple {
            clipRadius: 2
            x: control.spacing
            y: control.spacing
            width: parent.width - 2 * control.spacing
            height: parent.height - 2 * control.spacing
            pressed: control.up.pressed
            active: control.up.pressed || control.up.hovered || control.visualFocus
            color: control.Material.rippleColor
        }

        Rectangle {
            x: (parent.width - width) / 2
            y: (parent.height - height) / 2
            width: Math.min(parent.width / 3, parent.height / 3)
            height: 2
            color: enabled ? control.Material.foreground : control.Material.spinBoxDisabledIconColor
        }
        Rectangle {
            x: (parent.width - width) / 2
            y: (parent.height - height) / 2
            width: 2
            height: Math.min(parent.width / 3, parent.height / 3)
            color: enabled ? control.Material.foreground : control.Material.spinBoxDisabledIconColor
        }
    }

    down.indicator: Item {
        x: control.mirrored ? control.width - width : 0
        implicitWidth: control.Material.touchTarget
        implicitHeight: control.Material.touchTarget
        height: control.height
        width: height

        Ripple {
            clipRadius: 2
            x: control.spacing
            y: control.spacing
            width: parent.width - 2 * control.spacing
            height: parent.height - 2 * control.spacing
            pressed: control.down.pressed
            active: control.down.pressed || control.down.hovered || control.visualFocus
            color: control.Material.rippleColor
        }

        Rectangle {
            x: (parent.width - width) / 2
            y: (parent.height - height) / 2
            width: parent.width / 3
            height: 2
            color: enabled ? control.Material.foreground : control.Material.spinBoxDisabledIconColor
        }
    }

    background: MaterialTextContainer {
        implicitWidth: 140
        implicitHeight: control.Material.textFieldHeight

        outlineColor: (enabled && control.hovered) ? control.Material.primaryTextColor : control.Material.hintTextColor
        focusedOutlineColor: control.Material.accentColor
        controlHasActiveFocus: control.activeFocus
        controlHasText: true
        horizontalPadding: control.Material.textFieldHorizontalPadding
    }
}
