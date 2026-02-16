// Copyright (C) 2017 The Qt Company Ltd.
// SPDX-License-Identifier: LicenseRef-Qt-Commercial OR LGPL-3.0-only OR GPL-2.0-only OR GPL-3.0-only
// Qt-Security score:significant reason:default

import QtQuick
import QtQuick.Templates as T
import QtQuick.Controls.Imagine
import QtQuick.Controls.Imagine.impl

T.ProgressBar {
    id: control

    implicitWidth: Math.max(implicitBackgroundWidth + leftInset + rightInset,
                            implicitContentWidth + leftPadding + rightPadding)
    implicitHeight: Math.max(implicitBackgroundHeight + topInset + bottomInset,
                             implicitContentHeight + topPadding + bottomPadding)

    topPadding: background ? background.topPadding : 0
    leftPadding: background ? background.leftPadding : 0
    rightPadding: background ? background.rightPadding : 0
    bottomPadding: background ? background.bottomPadding : 0

    topInset: background ? -background.topInset || 0 : 0
    leftInset: background ? -background.leftInset || 0 : 0
    rightInset: background ? -background.rightInset || 0 : 0
    bottomInset: background ? -background.bottomInset || 0 : 0

    contentItem: Item {
        implicitWidth: control.indeterminate ? animation.implicitWidth || progress.implicitWidth : progress.implicitWidth
        implicitHeight: control.indeterminate ? animation.implicitHeight || progress.implicitHeight : progress.implicitHeight
        scale: control.mirrored ? -1 : 1

        readonly property bool hasMask: mask.status !== Image.Null

        readonly property NinePatchImage progress: NinePatchImage {
            parent: control.contentItem
            width: control.position * parent.width
            height: parent.height
            visible: !control.indeterminate && !control.contentItem.hasMask

            source: Imagine.url + "progressbar-progress"
            NinePatchImageSelector on source {
                states: [
                    {"disabled": !control.enabled},
                    {"indeterminate": control.indeterminate},
                    {"mirrored": control.mirrored},
                    {"hovered": control.enabled && control.hovered}
                ]
            }
        }

        readonly property AnimatedImage animation: AnimatedImage {
            parent: control.contentItem
            width: parent.width
            height: parent.height
            playing: control.indeterminate
            visible: control.indeterminate && !control.contentItem.hasMask

            source: Imagine.url + "progressbar-animation"
            AnimatedImageSelector on source {
                states: [
                    {"disabled": !control.enabled},
                    {"mirrored": control.mirrored},
                    {"hovered": control.enabled && control.hovered}
                ]
            }
        }

        readonly property NinePatchImage mask: NinePatchImage {
            width: control.availableWidth
            height: control.availableHeight
            visible: false

            source: Imagine.url + "progressbar-mask"
            NinePatchImageSelector on source {
                states: [
                    {"disabled": !control.enabled},
                    {"indeterminate": control.indeterminate},
                    {"mirrored": control.mirrored},
                    {"hovered": control.enabled && control.hovered}
                ]
            }
        }

        readonly property OpacityMask effect: OpacityMask {
            parent: control.contentItem
            width: source.width
            height: source.height
            source: control.indeterminate ? control.contentItem.animation : control.contentItem.progress

            maskSource: ShaderEffectSource {
                sourceItem: control.contentItem.mask
                sourceRect: Qt.rect(0, 0, control.contentItem.effect.width, control.contentItem.effect.height)
            }
        }
    }

    background: NinePatchImage {
        source: Imagine.url + "progressbar-background"
        NinePatchImageSelector on source {
            states: [
                {"disabled": !control.enabled},
                {"indeterminate": control.indeterminate},
                {"mirrored": control.mirrored},
                {"hovered": control.enabled && control.hovered}
            ]
        }
    }
}
