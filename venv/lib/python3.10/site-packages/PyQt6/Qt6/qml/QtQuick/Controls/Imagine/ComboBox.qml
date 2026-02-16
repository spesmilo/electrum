// Copyright (C) 2017 The Qt Company Ltd.
// SPDX-License-Identifier: LicenseRef-Qt-Commercial OR LGPL-3.0-only OR GPL-2.0-only OR GPL-3.0-only
// Qt-Security score:significant reason:default

pragma ComponentBehavior: Bound

import QtQuick
import QtQuick.Window
import QtQuick.Templates as T
import QtQuick.Controls.Imagine
import QtQuick.Controls.Imagine.impl

T.ComboBox {
    id: control

    implicitWidth: Math.max(implicitBackgroundWidth + leftInset + rightInset,
                            implicitContentWidth + (background ? background.leftPadding + background.rightPadding : 0))
    implicitHeight: Math.max(implicitBackgroundHeight + topInset + bottomInset,
                             Math.max(implicitContentHeight,
                                      implicitIndicatorHeight) + (background ? background.topPadding + background.bottomPadding : 0))

    leftPadding: padding + (!control.mirrored || !indicator || !indicator.visible ? 0 : indicator.width + spacing)
    rightPadding: padding + (control.mirrored || !indicator || !indicator.visible ? 0 : indicator.width + spacing)

    topInset: background ? -background.topInset || 0 : 0
    leftInset: background ? -background.leftInset || 0 : 0
    rightInset: background ? -background.rightInset || 0 : 0
    bottomInset: background ? -background.bottomInset || 0 : 0

    delegate: ItemDelegate {
        required property var model
        required property int index

        width: ListView.view.width
        text: model[control.textRole]
        font.weight: control.currentIndex === index ? Font.DemiBold : Font.Normal
        highlighted: control.highlightedIndex === index
        hoverEnabled: control.hoverEnabled
    }

    indicator: Image {
        x: control.mirrored ? control.padding : control.width - width - control.padding
        y: control.topPadding + (control.availableHeight - height) / 2

        source: Imagine.url + "combobox-indicator"
        ImageSelector on source {
            states: [
                {"disabled": !control.enabled},
                {"pressed": control.pressed},
                {"editable": control.editable},
                {"open": control.down},
                {"focused": control.visualFocus},
                {"mirrored": control.mirrored},
                {"hovered": control.enabled && control.hovered},
                {"flat": control.flat}
            ]
        }
    }

    contentItem: T.TextField {
        topPadding: control.background ? control.background.topPadding : 0
        leftPadding: control.background ? control.background.leftPadding : 0
        rightPadding: control.background ? control.background.rightPadding : 0
        bottomPadding: control.background ? control.background.bottomPadding : 0

        text: control.editable ? control.editText : control.displayText

        enabled: control.editable
        autoScroll: control.editable
        readOnly: control.down
        inputMethodHints: control.inputMethodHints
        validator: control.validator
        selectByMouse: control.selectTextByMouse

        color: control.flat ? control.palette.windowText : control.editable ? control.palette.text : control.palette.buttonText
        selectionColor: control.palette.highlight
        selectedTextColor: control.palette.highlightedText
        verticalAlignment: Text.AlignVCenter
    }

    background: NinePatchImage {
        source: Imagine.url + "combobox-background"
        NinePatchImageSelector on source {
            states: [
                {"disabled": !control.enabled},
                {"pressed": control.pressed},
                {"editable": control.editable},
                {"open": control.down},
                {"focused": control.visualFocus || (control.editable && control.activeFocus)},
                {"mirrored": control.mirrored},
                {"hovered": control.enabled && control.hovered},
                {"flat": control.flat}
            ]
        }
    }

    popup: T.Popup {
        width: control.width
        height: Math.min(contentItem.implicitHeight + topPadding + bottomPadding, control.Window.height - topMargin - bottomMargin)

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
            source: Imagine.url + "combobox-popup"
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
