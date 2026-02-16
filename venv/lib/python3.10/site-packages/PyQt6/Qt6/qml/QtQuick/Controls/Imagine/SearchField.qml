// Copyright (C) 2025 The Qt Company Ltd.
// SPDX-License-Identifier: LicenseRef-Qt-Commercial OR LGPL-3.0-only OR GPL-2.0-only OR GPL-3.0-only
// Qt-Security score:significant reason:default

import QtQuick
import QtQuick.Templates as T
import QtQuick.Controls.Imagine
import QtQuick.Controls.Imagine.impl

T.SearchField {
    id: control

    // Note: the width of the indicators are calculated into the padding
    implicitWidth: Math.max(implicitBackgroundWidth + leftInset + rightInset,
                            contentItem.implicitWidth + leftPadding + rightPadding)
    implicitHeight: Math.max(implicitBackgroundHeight + topInset + bottomInset,
                             implicitContentHeight + topPadding + bottomPadding,
                             searchIndicator.implicitIndicatorHeight, clearIndicator.implicitIndicatorHeight)

    topPadding: background ? background.topPadding : 0
    leftPadding: (background ? background.leftPadding : 0) + (control.mirrored ? __clearIndicatorWidth : __searchIndicatorWidth)
    rightPadding: (background ? background.rightPadding : 0) + (control.mirrored ? __searchIndicatorWidth : __clearIndicatorWidth)
    bottomPadding: background ? background.bottomPadding : 0

    topInset: background ? -background.topInset || 0 : 0
    leftInset: background ? -background.leftInset || 0 : 0
    rightInset: background ? -background.rightInset || 0 : 0
    bottomInset: background ? -background.bottomInset || 0 : 0

    readonly property real __clearIndicatorWidth: !clearIndicator.indicator || !clearIndicator.indicator.visible
                                             ? 0 : clearIndicator.indicator.width
    readonly property real __searchIndicatorWidth: !searchIndicator.indicator || !searchIndicator.indicator.visible
                                              ? 0 : searchIndicator.indicator.width

    delegate: ItemDelegate {
        width: ListView.view.width
        text: model[control.textRole]
        palette.text: control.palette.text
        palette.highlightedText: control.palette.highlightedText
        font.weight: control.currentIndex === index ? Font.DemiBold : Font.Normal
        highlighted: control.highlightedIndex === index
        hoverEnabled: control.hoverEnabled
        required property var model
        required property int index
    }

    searchIndicator.indicator: NinePatchImage {
        x: control.mirrored ? control.width - width : 0
        y: Math.round((control.height - height) / 2)
        height: control.height

        source: Imagine.url + "searchfield-indicator"
        NinePatchImageSelector on source {
            states: [
                {"search": true},
                {"disabled": !control.searchIndicator.indicator.enabled},
                {"editable": !control.editable},
                {"pressed": control.searchIndicator.pressed},
                {"focused": control.visualFocus},
                {"mirrored": control.mirrored},
                {"hovered": control.searchIndicator.hovered}
            ]
        }
    }

    clearIndicator.indicator: NinePatchImage {
        x: control.mirrored ? 0 : control.width - width
        y: Math.round((control.height - height) / 2)
        height: control.height
        visible: control.text.length > 0

        source: Imagine.url + "searchfield-indicator"
        NinePatchImageSelector on source {
            states: [
                {"clear": true},
                {"disabled": !control.clearIndicator.indicator.enabled},
                {"editable": !control.editable},
                {"pressed": control.clearIndicator.pressed},
                {"focused": control.visualFocus},
                {"mirrored": control.mirrored},
                {"hovered": control.clearIndicator.hovered}
            ]
        }
    }

    contentItem: T.TextField {
        z: 2

        text: control.text

        color: control.flat ? control.palette.windowText : control.palette.text
        selectionColor: control.palette.highlight
        selectedTextColor: control.palette.highlightedText
        verticalAlignment: Text.AlignVCenter
    }

    background: NinePatchImage {
        source: Imagine.url + "searchfield-background"
        NinePatchImageSelector on source {
            states: [
                {"disabled": !control.enabled},
                {"editable": !control.editable},
                {"focused": control.activeFocus},
                {"mirrored": control.mirrored},
                {"hovered": control.enabled && control.hovered}
            ]
        }
    }

    popup: T.Popup {
        y: control.height
        width: control.width
        height: Math.min(contentItem.implicitHeight, control.Window.height - control.y - control.height - control.padding)

        topMargin: background.topInset
        bottomMargin: background.bottomInset

        topPadding: background.topPadding
        leftPadding: background.leftPadding
        rightPadding: background.rightPadding
        bottomPadding: background.bottomPadding

        topInset: background ? -background.topInset || 0 : 0
        leftInset: background ? -background.leftInset || 0 : 0
        rightInset: background ? -background.rightInset || 0 : 0
        bottomInset: background ? -background.bottomInset || 0 : 0

        palette.text: control.palette.text
        palette.highlight: control.palette.highlight
        palette.highlightedText: control.palette.highlightedText
        palette.windowText: control.palette.windowText
        palette.buttonText: control.palette.buttonText

        contentItem: ListView {
            clip: true
            implicitHeight: contentHeight
            model: control.delegateModel
            currentIndex: control.highlightedIndex
            highlightMoveDuration: 0

            T.ScrollIndicator.vertical: ScrollIndicator { }
        }

        background: NinePatchImage {
            source: Imagine.url + "searchfield-popup"
            NinePatchImageSelector on source {
                states: [
                    {"disabled": !control.enabled},
                    {"pressed": control.pressed},
                    {"editable": control.editable},
                    {"focused": control.visualFocus || (control.editable && control.activeFocus)},
                    {"mirrored": control.mirrored},
                    {"hovered": control.enabled && control.hovered},
                    {"flat": control.flat}
                ]
            }
        }
    }
}
