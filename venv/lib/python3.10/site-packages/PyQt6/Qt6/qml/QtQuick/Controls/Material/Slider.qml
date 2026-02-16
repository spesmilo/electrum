// Copyright (C) 2022 The Qt Company Ltd.
// SPDX-License-Identifier: LicenseRef-Qt-Commercial OR LGPL-3.0-only OR GPL-2.0-only OR GPL-3.0-only
// Qt-Security score:significant reason:default

import QtQuick
import QtQuick.Templates as T
import QtQuick.Controls.impl
import QtQuick.Controls.Material
import QtQuick.Controls.Material.impl

T.Slider {
    id: control

    implicitWidth: Math.max(implicitBackgroundWidth + leftInset + rightInset,
                            implicitHandleWidth + leftPadding + rightPadding)
    implicitHeight: Math.max(implicitBackgroundHeight + topInset + bottomInset,
                             implicitHandleHeight + topPadding + bottomPadding)

    padding: 6

    // The Slider is discrete if all of the following requirements are met:
    // * stepSize is positive
    // * snapMode is set to SnapAlways
    // * the difference between to and from is cleanly divisible by the stepSize
    // * the number of tick marks intended to be rendered is less than the width to height ratio, or vice versa for vertical sliders.
    readonly property real __steps: Math.abs(to - from) / stepSize
    readonly property bool __isDiscrete: stepSize >= Number.EPSILON
        && snapMode === Slider.SnapAlways
        && Math.abs(Math.round(__steps) - __steps) < Number.EPSILON
        && Math.floor(__steps) < (horizontal ? background.width / background.height : background.height / background.width)

    handle: SliderHandle {
        x: control.leftPadding + (control.horizontal ? control.visualPosition * (control.availableWidth - width) : (control.availableWidth - width) / 2)
        y: control.topPadding + (control.horizontal ? (control.availableHeight - height) / 2 : control.visualPosition * (control.availableHeight - height))
        value: control.value
        handleHasFocus: control.visualFocus
        handlePressed: control.pressed
        handleHovered: control.hovered
    }

    background: Item {
        x: control.leftPadding + (control.horizontal ? 0 : (control.availableWidth - width) / 2)
        y: control.topPadding + (control.horizontal ? (control.availableHeight - height) / 2 : 0)
        implicitWidth: control.horizontal ? 200 : 48
        implicitHeight: control.horizontal ? 48 : 200
        width: control.horizontal ? control.availableWidth : 4
        height: control.horizontal ? 4 : control.availableHeight

        Rectangle {
            x: (control.horizontal ? (control.implicitHandleWidth / 2) - (control.__isDiscrete ? 2 : 0) : 0)
            y: (control.horizontal ? 0 : (control.implicitHandleHeight / 2) - (control.__isDiscrete ? 2 : 0))
            width: parent.width - (control.horizontal ? (control.implicitHandleWidth - (control.__isDiscrete ? 4 : 0)) : 0)
            height: parent.height - (control.horizontal ? 0 : (control.implicitHandleHeight - (control.__isDiscrete ? 4 : 0)))
            scale: control.horizontal && control.mirrored ? -1 : 1
            radius: Math.min(width, height) / 2
            color: control.enabled ? Color.transparent(control.Material.accentColor, 0.33) : control.Material.sliderDisabledColor

            Rectangle {
                x: control.horizontal ? 0 : (parent.width - width) / 2
                y: control.horizontal ? (parent.height - height) / 2 : control.visualPosition * parent.height
                width: control.horizontal ? control.position * parent.width : 4
                height: control.horizontal ? 4 : control.position * parent.height
                radius: Math.min(width, height) / 2
                color: control.enabled ? control.Material.accentColor : control.Material.sliderDisabledColor
            }

            // Declaring this as a property (in combination with the parent binding below) avoids ids,
            // which prevent deferred execution.
            property Repeater repeater: Repeater {
                parent: control.background.children[0]
                model: control.__isDiscrete ? Math.floor(control.__steps) + 1 : 0
                delegate: Rectangle {
                    width: 2
                    height: 2
                    radius: 2
                    x: control.horizontal ? (parent.width - width * 2) * currentPosition + (width / 2) : (parent.width - width) / 2
                    y: control.horizontal ? (parent.height - height) / 2 : (parent.height - height * 2) * currentPosition + (height / 2)
                    color: (control.horizontal && control.visualPosition > currentPosition)
                           || (!control.horizontal && control.visualPosition <= currentPosition)
                           ? control.Material.primaryHighlightedTextColor : control.Material.accentColor

                    required property int index
                    readonly property real currentPosition: index / (parent.repeater.count - 1)
                }
            }
        }
    }
}
