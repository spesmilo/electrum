// Copyright (C) 2025 The Qt Company Ltd.
// SPDX-License-Identifier: LicenseRef-Qt-Commercial OR LGPL-3.0-only OR GPL-2.0-only OR GPL-3.0-only
// Qt-Security score:significant reason:default

import QtQuick
import QtQuick.Templates as T
import QtQuick.Controls.impl
import QtQuick.Controls.Universal
import QtQuick.Controls.Universal.impl

T.SearchField {
    id: control

    implicitWidth: Math.max(implicitBackgroundWidth + leftInset + rightInset,
                            implicitContentWidth + leftPadding + rightPadding)
                   + searchIndicator.implicitIndicatorWidth + clearIndicator.implicitIndicatorWidth
    implicitHeight: Math.max(implicitBackgroundHeight + topInset + bottomInset,
                             implicitContentHeight + topPadding + bottomPadding,
                             searchIndicator.implicitIndicatorHeight + topPadding + bottomPadding)

    leftPadding: padding + (control.mirrored ? __clearIndicatorWidth : __searchIndicatorWidth)
    rightPadding: padding + (control.mirrored ? __searchIndicatorWidth : __clearIndicatorWidth)

    readonly property real __clearIndicatorWidth: !clearIndicator.indicator || !clearIndicator.indicator.visible
                                             ? 0 : clearIndicator.indicator.width + spacing
    readonly property real __searchIndicatorWidth: !searchIndicator.indicator || !searchIndicator.indicator.visible
                                              ? 0 : searchIndicator.indicator.width + spacing

    Universal.theme: activeFocus ? Universal.Light : undefined

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

    searchIndicator.indicator: Item {
        x: !control.mirrored ? control.padding : control.width - width - control.padding
        y: control.topPadding + (control.availableHeight - height) / 2
        implicitWidth: 28
        implicitHeight: 28

        Rectangle {
            width: parent.width
            height: parent.height
            color: control.activeFocus ? control.Universal.accent :
                   control.searchIndicator.pressed ? control.Universal.baseMediumLowColor :
                   control.searchIndicator.hovered ? control.Universal.baseLowColor : "transparent"
            visible: control.searchIndicator.pressed || control.searchIndicator.hovered
            opacity: control.activeFocus && !control.searchIndicator.pressed ? 0.4 : 1.0
        }

        ColorImage {
            x: (parent.width - width) / 2
            y: (parent.height - height) / 2
            width: 20
            height: 20
            color: !enabled ? control.Universal.chromeDisabledLowColor :
                              control.activeFocus ? control.Universal.chromeBlackHighColor : control.Universal.baseHighColor
            source: "qrc:/qt-project.org/imports/QtQuick/Controls/Universal/images/search-magnifier.png"
        }
    }

    clearIndicator.indicator: Item {
        x: control.mirrored ? control.padding : control.width - width - control.padding
        y: control.topPadding + (control.availableHeight - height) / 2
        implicitWidth: 28
        implicitHeight: 28
        visible: control.text.length > 0

        Rectangle {
            width: parent.width
            height: parent.height
            color: control.activeFocus ? control.Universal.accent :
                   control.clearIndicator.pressed ? control.Universal.baseMediumLowColor :
                   control.clearIndicator.hovered ? control.Universal.baseLowColor : "transparent"
            visible: control.clearIndicator.pressed || control.clearIndicator.hovered
            opacity: control.activeFocus && !control.clearIndicator.pressed ? 0.4 : 1.0
        }

        ColorImage {
            x: (parent.width - width) / 2
            y: (parent.height - height) / 2
            width: 20
            height: 20
            color: !enabled ? control.Universal.chromeDisabledLowColor :
                              control.activeFocus ? control.Universal.chromeBlackHighColor : control.Universal.baseHighColor
            source: "qrc:/qt-project.org/imports/QtQuick/Controls/Universal/images/close_big.png"
        }
    }

    contentItem: T.TextField {
        leftPadding: !control.mirrored ? 6 : 0
        rightPadding: !control.mirrored ? 6 : 0

        text: control.text

        color: !control.enabled ? control.Universal.chromeDisabledLowColor :
                                  control.activeFocus ? control.Universal.chromeBlackHighColor : control.Universal.foreground
        selectionColor: control.Universal.accent
        selectedTextColor: control.Universal.chromeWhiteColor
        verticalAlignment: TextInput.AlignVCenter
    }

    background: Rectangle {
        implicitWidth: 120
        implicitHeight: 32

        border.width: 2 // TextControlBorderThemeThickness
        border.color: !control.enabled ? control.Universal.baseLowColor :
                       control.activeFocus ? control.Universal.accent :
                       control.hovered ? control.Universal.baseMediumColor : control.Universal.chromeDisabledLowColor
        color: control.enabled ? control.Universal.background : control.Universal.baseLowColor
    }

    popup: T.Popup {
        y: control.height
        width: control.width
        height: Math.min(contentItem.implicitHeight, control.Window.height - control.y - control.height - control.padding)
        topMargin: 6
        bottomMargin: 6

        Universal.theme: control.Universal.theme
        Universal.accent: control.Universal.accent

        contentItem: ListView {
            clip: true
            implicitHeight: contentHeight
            model: control.delegateModel
            currentIndex: control.highlightedIndex
            highlightMoveDuration: 0

            T.ScrollIndicator.vertical: ScrollIndicator { }
        }

        background: Rectangle {
            color: control.Universal.chromeMediumLowColor
            border.color: control.Universal.chromeHighColor
            border.width: 1
        }
    }
}
