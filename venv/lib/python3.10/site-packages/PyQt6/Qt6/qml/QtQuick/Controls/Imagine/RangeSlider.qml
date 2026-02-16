// Copyright (C) 2017 The Qt Company Ltd.
// SPDX-License-Identifier: LicenseRef-Qt-Commercial OR LGPL-3.0-only OR GPL-2.0-only OR GPL-3.0-only
// Qt-Security score:significant reason:default

import QtQuick
import QtQuick.Templates as T
import QtQuick.Controls.Imagine
import QtQuick.Controls.Imagine.impl

T.RangeSlider {
    id: control

    implicitWidth: Math.max(implicitBackgroundWidth + leftInset + rightInset,
                            first.implicitHandleWidth + leftPadding + rightPadding,
                            second.implicitHandleWidth + leftPadding + rightPadding)
    implicitHeight: Math.max(implicitBackgroundHeight + topInset + bottomInset,
                             first.implicitHandleHeight + topPadding + bottomPadding,
                             second.implicitHandleHeight + topPadding + bottomPadding)

    topPadding: background ? background.topPadding : 0
    leftPadding: background ? background.leftPadding : 0
    rightPadding: background ? background.rightPadding : 0
    bottomPadding: background ? background.bottomPadding : 0

    topInset: background ? -background.topInset || 0 : 0
    leftInset: background ? -background.leftInset || 0 : 0
    rightInset: background ? -background.rightInset || 0 : 0
    bottomInset: background ? -background.bottomInset || 0 : 0

    first.handle: Image {
        x: control.leftPadding + (control.horizontal ? control.first.visualPosition * (control.availableWidth - width) : (control.availableWidth - width) / 2)
        y: control.topPadding + (control.horizontal ? (control.availableHeight - height) / 2 : control.first.visualPosition * (control.availableHeight - height))

        source: control.Imagine.url + "rangeslider-handle"
        ImageSelector on source {
            states: [
                {"first": true},
                {"vertical": control.vertical},
                {"horizontal": control.horizontal},
                {"disabled": !control.enabled},
                {"pressed": control.first.pressed},
                {"focused": control.first.handle?.activeFocus ?? false},
                {"mirrored": control.mirrored},
                {"hovered": control.first.hovered}
            ]
        }
    }

    second.handle: Image {
        x: control.leftPadding + (control.horizontal ? control.second.visualPosition * (control.availableWidth - width) : (control.availableWidth - width) / 2)
        y: control.topPadding + (control.horizontal ? (control.availableHeight - height) / 2 : control.second.visualPosition * (control.availableHeight - height))

        source: control.Imagine.url + "rangeslider-handle"
        ImageSelector on source {
            states: [
                {"second": true},
                {"vertical": control.vertical},
                {"horizontal": control.horizontal},
                {"disabled": !control.enabled},
                {"pressed": control.second.pressed},
                {"focused": control.second.handle?.activeFocus ?? false},
                {"mirrored": control.mirrored},
                {"hovered": control.second.hovered}
            ]
        }
    }

    background: NinePatchImage {
        scale: control.horizontal && control.mirrored ? -1 : 1

        source: control.Imagine.url + "rangeslider-background"
        NinePatchImageSelector on source {
            states: [
                {"vertical": control.vertical},
                {"horizontal": control.horizontal},
                {"disabled": !control.enabled},
                {"focused": control.visualFocus},
                {"mirrored": control.mirrored},
                {"hovered": control.enabled && control.hovered}
            ]
        }

        NinePatchImage {
            readonly property real handleWidth: control.first.handle ? control.first.handle.width : 0
            readonly property real handleHeight: control.first.handle ? control.first.handle.height : 0

            x: control.horizontal ? handleWidth / 2 + control.first.position * (parent.width - handleWidth) : (parent.width - width) / 2
            y: control.horizontal ? (parent.height - height) / 2 : handleHeight / 2 + control.second.visualPosition * (parent.height - handleHeight)
            width: control.horizontal ? control.second.position * (parent.width - handleWidth) - control.first.position * (parent.width - handleWidth) : parent.width
            height: control.vertical ? control.second.position * (parent.height - handleHeight) - control.first.position * (parent.height - handleHeight): parent.height

            source: control.Imagine.url + "rangeslider-progress"
            NinePatchImageSelector on source {
                states: [
                    {"vertical": control.vertical},
                    {"horizontal": control.horizontal},
                    {"disabled": !control.enabled},
                    {"focused": control.visualFocus},
                    {"mirrored": control.mirrored},
                    {"hovered": control.enabled && control.hovered}
                ]
            }
        }
    }
}
