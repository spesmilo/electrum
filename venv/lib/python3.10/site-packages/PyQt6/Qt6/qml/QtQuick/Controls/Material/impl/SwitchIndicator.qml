// Copyright (C) 2017 The Qt Company Ltd.
// SPDX-License-Identifier: LicenseRef-Qt-Commercial OR LGPL-3.0-only OR GPL-2.0-only OR GPL-3.0-only
// Qt-Security score:significant reason:default

import QtQuick
import QtQuick.Templates as T
import QtQuick.Controls.impl
import QtQuick.Controls.Material
import QtQuick.Controls.Material.impl

Rectangle {
    id: indicator
    width: control.Material.switchIndicatorWidth
    height: control.Material.switchIndicatorHeight
    radius: height / 2
    y: parent.height / 2 - height / 2
    color: control.enabled
        ? (control.checked
           ? control.Material.switchCheckedTrackColor : control.Material.switchUncheckedTrackColor)
        : (control.checked
           ? control.Material.switchDisabledCheckedTrackColor
           : control.Material.switchDisabledUncheckedTrackColor)
    border.width: 2
    border.color: control.enabled
        ? (control.checked ? control.Material.switchCheckedTrackColor : control.Material.switchUncheckedHandleColor)
        : (control.checked ? control.Material.switchDisabledCheckedTrackColor : control.Material.switchDisabledUncheckedTrackBorderColor)

    property T.AbstractButton control
    property alias handle: handle

    Behavior on color {
        ColorAnimation {
            duration: 200
        }
    }
    Behavior on border.color {
        ColorAnimation {
            duration: 200
        }
    }

    Rectangle {
        id: handle
        x: Math.max(offset, Math.min(parent.width - offset - width,
            indicator.control.visualPosition * parent.width - (width / 2)))
        y: (parent.height - height) / 2
        // We use scale to allow us to enlarge the circle from the center,
        // as using width/height will cause it to jump due to the position x/y bindings.
        // However, a large enough scale on certain displays will show the triangles
        // that make up the circle, so instead we make sure that the circle is always
        // its largest size so that more triangles are used, and downscale instead.
        width: normalSize * largestScale
        height: normalSize * largestScale
        radius: width / 2
        color: indicator.control.enabled
            ? (indicator.control.checked
               ? indicator.control.Material.switchCheckedHandleColor
               : indicator.control.hovered
                    ? indicator.control.Material.switchUncheckedHoveredHandleColor : indicator.control.Material.switchUncheckedHandleColor)
            : (indicator.control.checked
               ? indicator.control.Material.switchDisabledCheckedHandleColor
               : indicator.control.Material.switchDisabledUncheckedHandleColor)
        scale: indicator.control.down ? 1 : (indicator.control.checked ? checkedSize / largestSize : normalSize / largestSize)

        readonly property int offset: 2
        readonly property real normalSize: !hasIcon ? indicator.control.Material.switchNormalHandleHeight : checkedSize
        readonly property real checkedSize: indicator.control.Material.switchCheckedHandleHeight
        readonly property real largestSize: indicator.control.Material.switchLargestHandleHeight
        readonly property real largestScale: largestSize / normalSize
        readonly property bool hasIcon: indicator.control.icon.name.length > 0
            || indicator.control.icon.source.toString().length > 0

        Behavior on x {
            enabled: !indicator.control.pressed
            SmoothedAnimation {
                duration: 300
            }
        }

        Behavior on scale {
            NumberAnimation {
                duration: 100
            }
        }

        Behavior on color {
            ColorAnimation {
                duration: 200
            }
        }

        IconImage {
            x: (parent.width - width) / 2
            y: (parent.height - height) / 2
            name: indicator.control.icon.name
            source: indicator.control.icon.source
            sourceSize: Qt.size(indicator.control.icon.width, indicator.control.icon.height)
            color: indicator.control.icon.color
            visible: handle.hasIcon
        }
    }
}
