// Copyright (C) 2025 The Qt Company Ltd.
// SPDX-License-Identifier: LicenseRef-Qt-Commercial OR LGPL-3.0-only OR GPL-2.0-only OR GPL-3.0-only
// Qt-Security score:significant reason:default

pragma ComponentBehavior: Bound

import QtQuick
import QtQuick.Window
import QtQuick.Controls.impl
import QtQuick.Templates as T
import QtQuick.Controls.Material
import QtQuick.Controls.Material.impl

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

    delegate: MenuItem {
        width: ListView.view.width
        text: model[control.textRole]
        font.weight: control.currentIndex === index ? Font.DemiBold : Font.Normal
        highlighted: control.highlightedIndex === index
        hoverEnabled: control.hoverEnabled

        Material.foreground: control.currentIndex === index ? ListView.view.contentItem.Material.accent : ListView.view.contentItem.Material.foreground

        required property var model
        required property int index
    }

    searchIndicator.indicator: Item {
        x: !control.mirrored ? 10 : control.width - width - 10
        y: control.topPadding + (control.availableHeight - height) / 2
        height: control.height
        width: height / 2

        ColorImage {
            x: (parent.width - width) / 2
            y: (parent.height - height) / 2

            source: "qrc:/qt-project.org/imports/QtQuick/Controls/Material/images/search-magnifier.png"
            color: control.enabled ? control.Material.foreground : control.Material.hintTextColor
        }
    }

    clearIndicator.indicator: Item {
        x: control.mirrored ? 10 : control.width - width - 10
        y: control.topPadding + (control.availableHeight - height) / 2
        height: control.height
        width: height / 2
        visible: control.text.length > 0

        ColorImage {
            x: (parent.width - width) / 2
            y: (parent.height - height) / 2

            source: "qrc:/qt-project.org/imports/QtQuick/Controls/Material/images/close_circle.png"
            color: control.enabled ? control.Material.foreground : control.Material.hintTextColor
        }
    }

    contentItem: T.TextField {
        leftPadding: Material.textFieldHorizontalPadding
        rightPadding: Material.textFieldHorizontalPadding
        topPadding: Material.textFieldVerticalPadding
        bottomPadding: Material.textFieldVerticalPadding

        text: control.text

        color: control.enabled ? control.Material.foreground : control.Material.hintTextColor
        selectionColor: control.Material.accentColor
        selectedTextColor: control.Material.primaryHighlightedTextColor
        verticalAlignment: Text.AlignVCenter

        cursorDelegate: CursorDelegate { }
    }

    background: MaterialTextContainer {
        implicitWidth: 160
        implicitHeight: control.Material.textFieldHeight

        outlineColor: (enabled && control.hovered) ? control.Material.primaryTextColor : control.Material.hintTextColor
        focusedOutlineColor: control.Material.accentColor
        controlHasActiveFocus: control.activeFocus
        controlHasText: true
        horizontalPadding: control.Material.textFieldHorizontalPadding
    }

    popup: T.Popup {
        y: control.height
        width: control.width
        height: contentItem.implicitHeight > 0 ? Math.min(contentItem.implicitHeight + verticalPadding * 2, control.Window.height - control.y - control.height - control.padding) : 0
        topMargin: 10
        bottomMargin: 10
        verticalPadding: 10

        contentItem: ListView {
            clip: true
            implicitHeight: contentHeight
            model: control.delegateModel
            currentIndex: control.highlightedIndex
            highlightMoveDuration: 0

            T.ScrollIndicator.vertical: ScrollIndicator { }
        }

        background: Rectangle {
            radius: 5
            color: control.Material.dialogColor

            layer.enabled: control.enabled > 0
            layer.effect: RoundedElevationEffect {
                elevation: 4
                roundedScale: Material.ExtraSmallScale
            }
        }
    }
}
