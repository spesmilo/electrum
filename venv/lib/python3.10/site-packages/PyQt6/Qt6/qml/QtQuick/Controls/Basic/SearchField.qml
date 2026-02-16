// Copyright (C) 2025 The Qt Company Ltd.
// SPDX-License-Identifier: LicenseRef-Qt-Commercial OR LGPL-3.0-only OR GPL-2.0-only OR GPL-3.0-only
// Qt-Security score:significant reason:default

pragma ComponentBehavior: Bound

import QtQuick
import QtQuick.Controls.impl
import QtQuick.Templates as T

T.SearchField {
    id: control

    implicitWidth: Math.max(implicitBackgroundWidth + leftInset + rightInset,
                            implicitContentWidth + leftPadding + rightPadding)
    implicitHeight: Math.max(implicitBackgroundHeight + topInset + bottomInset,
                             implicitContentHeight + topPadding + bottomPadding,
                             searchIndicator.implicitIndicatorHeight + topPadding + bottomPadding,
                             clearIndicator.implicitIndicatorHeight + topPadding + bottomPadding)

    leftPadding: padding + (control.mirrored || !searchIndicator.indicator || !searchIndicator.indicator.visible ? 0 : searchIndicator.indicator.width + spacing)
    rightPadding: padding + (control.mirrored || !clearIndicator.indicator || !clearIndicator.indicator.visible ? 0 : clearIndicator.indicator.width + spacing)

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

    searchIndicator.indicator: Rectangle {
        implicitWidth: 28
        implicitHeight: 28

        x: !control.mirrored ? 3 : control.width - width - 3
        y: control.topPadding + (control.availableHeight - height) / 2
        color: control.palette.button

        ColorImage {
            x: (parent.width - width) / 2
            y: (parent.height - height) / 2
            color: control.palette.dark
            defaultColor: "#353637"
            source: "qrc:/qt-project.org/imports/QtQuick/Controls/Basic/images/search-magnifier.png"
            opacity: enabled ? 1 : 0.3
        }
    }

    clearIndicator.indicator: Rectangle {
        implicitWidth: 28
        implicitHeight: 28

        x: control.mirrored ? 3 : control.width - width - 3
        y: control.topPadding + (control.availableHeight - height) / 2
        visible: control.text.length > 0
        color: control.palette.button

        ColorImage {
            x: (parent.width - width) / 2
            y: (parent.height - height) / 2
            color: control.palette.dark
            defaultColor: "#353637"
            source: "qrc:/qt-project.org/imports/QtQuick/Controls/Basic/images/close_circle.png"
            opacity: enabled ? 1 : 0.3
        }
    }

    contentItem: T.TextField {
        leftPadding: control.searchIndicator.indicator && !control.mirrored ? 6 : 0
        rightPadding: control.clearIndicator.indicator && !control.mirrored ? 6 : 0
        topPadding: 6 - control.padding
        bottomPadding: 6 - control.padding

        text: control.text

        color: control.palette.text
        selectionColor: control.palette.highlight
        selectedTextColor: control.palette.highlightedText
        verticalAlignment: TextInput.AlignVCenter
    }

    background: Rectangle {
        implicitWidth: 200
        implicitHeight: 40

        color: control.palette.button
        border.width: (control.activeFocus || control.contentItem.activeFocus) ? 2 : 1
        border.color: (control.activeFocus || control.contentItem.activeFocus) ? control.palette.highlight : control.palette.mid
    }

    popup: T.Popup {
        y: control.height
        width: control.width
        height: Math.min(contentItem.implicitHeight, control.Window.height - control.y - control.height - control.padding)
        topMargin: 6
        bottomMargin: 6
        palette: control.palette

        contentItem: ListView {
            clip: true
            implicitHeight: contentHeight
            model: control.delegateModel
            currentIndex: control.highlightedIndex
            highlightMoveDuration: 0

            Rectangle {
                z: 10
                width: parent.width
                height: parent.height
                color: "transparent"
                border.color: control.palette.mid
            }

            T.ScrollIndicator.vertical: ScrollIndicator { }
        }

        background: Rectangle {
            color: control.palette.window
        }
    }
}
