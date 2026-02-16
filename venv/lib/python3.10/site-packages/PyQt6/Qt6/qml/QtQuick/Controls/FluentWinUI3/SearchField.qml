// Copyright (C) 2025 The Qt Company Ltd.
// SPDX-License-Identifier: LicenseRef-Qt-Commercial OR LGPL-3.0-only OR GPL-2.0-only OR GPL-3.0-only
// Qt-Security score:significant reason:default

pragma ComponentBehavior: Bound

import QtQuick
import QtQuick.Templates as T
import QtQuick.Controls.impl
import QtQuick.Controls.FluentWinUI3.impl as Impl

T.SearchField {
    id: control

    implicitWidth: Math.max(implicitBackgroundWidth + leftInset + rightInset,
                            implicitContentWidth + leftPadding + rightPadding)
                   + searchIndicator.implicitIndicatorWidth + clearIndicator.implicitIndicatorWidth
    implicitHeight: Math.max(implicitBackgroundHeight + topInset + bottomInset,
                             implicitContentHeight + topPadding + bottomPadding,
                             searchIndicator.implicitIndicatorHeight + topPadding + bottomPadding)

    spacing: __config.contentItem.spacing / 2 || 0

    topPadding: __config.topPadding || 0
    bottomPadding: __config.bottomPadding || 0

    readonly property real __clearIndicator: (!clearIndicator.indicator || !clearIndicator.indicator.visible ? 0 : clearIndicator.indicator.width + control.spacing)
    readonly property real __searchIndicator: (!searchIndicator.indicator || !searchIndicator.indicator.visible ? 0 : searchIndicator.indicator.width + control.spacing)
    leftPadding: __config.leftPadding + (control.mirrored ? __clearIndicator + __searchIndicator : 0)
    rightPadding: __config.rightPadding + (control.mirrored ? 0 : __clearIndicator + __searchIndicator)

    topInset: -__config.topInset || 0
    bottomInset: -__config.bottomInset || 0
    leftInset: -__config.leftInset || 0
    rightInset: -__config.rightInset || 0

    readonly property string __currentState: [
        !control.enabled && "disabled",
        (control.searchIndicator.pressed && control.clearIndicator.pressed) && "hovered",
        control.popup.visible && "open",
        (control.searchIndicator.pressed && control.clearIndicator.pressed) && "pressed"
    ].filter(Boolean).join("_") || "normal"
    readonly property var __config: (control.popup.visible
                                    ? Config.controls.editablecombobox[__currentState]
                                    : Config.controls.combobox[__currentState]) || {}

    readonly property Item __focusFrameTarget: null
    readonly property bool __isHighContrast: Application.styleHints.accessibility.contrastPreference === Qt.HighContrast

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

    searchIndicator.indicator: Impl.StyleImage {
        // use SpinBox indicator assets as they share the same style
        readonly property string __state: [
            (control.searchIndicator.hovered || control.searchIndicator.pressed) && "up",
            (control.searchIndicator.indicator.enabled && control.searchIndicator.hovered && !control.searchIndicator.pressed) && "hovered",
            (control.searchIndicator.indicator.enabled && control.searchIndicator.pressed) && "pressed",
            (!control.searchIndicator.indicator.enabled) && "disabled"
        ].filter(Boolean).join("_") || "normal"
        readonly property var indicatorConfig: Config.controls.spinbox[__state] || {}
        imageConfig: indicatorConfig.indicator_up_background

        x: !control.mirrored ? control.width - width - control.spacing : control.spacing
        y: control.topPadding + (control.availableHeight - height) / 2

        implicitWidth: 32
        implicitHeight: 24

        ColorImage {
            x: (parent.width - width) / 2
            y: (parent.height - height) / 2
            width: 13
            height: 13

            source: Qt.resolvedUrl("icons/search-magnifier")
            color: control.palette.placeholderText
            opacity: control.searchIndicator.pressed ? 0.7 : 1
        }
    }

    clearIndicator.indicator: Impl.StyleImage {
        // use SpinBox indicator assets as they share the same style
        readonly property string __state: [
            (control.clearIndicator.hovered || control.clearIndicator.pressed) && "down",
            (control.clearIndicator.indicator.enabled && control.clearIndicator.hovered && !control.clearIndicator.pressed) && "hovered",
            (control.clearIndicator.indicator.enabled && control.clearIndicator.pressed) && "pressed",
            (!control.clearIndicator.indicator.enabled) && "disabled"
        ].filter(Boolean).join("_") || "normal"
        readonly property var indicatorConfig: Config.controls.spinbox[__state] || {}
        imageConfig: indicatorConfig.indicator_down_background

        x: (!searchIndicator.indicator || !searchIndicator.indicator.visible)
           ? (!control.mirrored ? control.width - width - control.spacing : control.spacing)
           : (!control.mirrored ? control.width - width - (control.spacing * 2) - searchIndicator.indicator.width : searchIndicator.indicator.width + (control.spacing * 2))
        y: control.topPadding + (control.availableHeight - height) / 2
        implicitWidth: 32
        implicitHeight: 24
        visible: control.text.length > 0

        ColorImage {
            x: (parent.width - width) / 2
            y: (parent.height - height) / 2
            width: 13
            height: 13

            source: Qt.resolvedUrl("icons/close_big")
            color: control.palette.placeholderText
            opacity: control.clearIndicator.pressed ? 0.7 : 1
        }
    }

    contentItem: T.TextField {
        leftPadding: control.__config.label_contentItem.leftPadding
        rightPadding: control.__config.label_contentItem.rightPadding
        topPadding: control.__config.label_contentItem.topPadding
        bottomPadding: control.__config.label_contentItem.bottomPadding

        implicitHeight: Math.max(implicitBackgroundHeight + topInset + bottomInset,
                                 contentHeight + topPadding + bottomPadding)

        text: control.text

        color: control.palette.text
        selectionColor: control.palette.highlight
        selectedTextColor: control.palette.highlightedText
        horizontalAlignment: control.__config.label_text.textHAlignment
        verticalAlignment: control.__config.label_text.textVAlignment

        readonly property Item __focusFrameControl: control
    }

    background: ItemGroup {
        Impl.StyleImage {
            visible: !control.__isHighContrast
            imageConfig: control.__config.background
            Item {
                visible: control.popup.visible || control.activeFocus
                width: parent.width
                height: 2
                y: parent.height - height
                Impl.FocusStroke {
                    width: parent.width
                    height: parent.height
                    radius: control.popup.visible ? 0 : control.__config.background.bottomOffset
                    color: control.palette.accent
                }
            }
        }
        Rectangle {
            visible: control.__isHighContrast
            implicitWidth: control.__config.background.width
            implicitHeight: control.__config.background.height
            color: control.palette.window
            border.color: control.hovered ? control.palette.accent : control.palette.text
            radius: 4
        }
    }

    popup: T.Popup {
        y: control.height
        width: control.width
        height: control.suggestionCount > 0 ? Math.min(contentItem.implicitHeight + topPadding + bottomPadding, control.Window.height - topMargin - bottomMargin) : 0
        topMargin: 8
        bottomMargin: 8
        palette: control.palette

        topPadding: control.__config.popup_contentItem.topPadding || 0
        leftPadding: control.__config.popup_contentItem.leftPadding || 0
        rightPadding: control.__config.popup_contentItem.rightPadding || 0
        bottomPadding: control.__config.popup_contentItem.bottomPadding || 0

        contentItem: ListView {
            clip: true
            implicitHeight: contentHeight
            model: control.delegateModel
            currentIndex: control.highlightedIndex
            highlightMoveDuration: 0
        }

        enter: Transition {
            NumberAnimation { property: "height"; from: control.popup.height / 3; to: control.popup.height; easing.type: Easing.OutCubic; duration: 250 }
        }

        background: ItemGroup {
            Impl.StyleImage {
                visible: !control.__isHighContrast
                imageConfig: control.__config.popup_background.filePath ? control.__config.popup_background : Config.controls.popup["normal"].background // fallback to regular popup
            }
            Rectangle {
                visible: control.__isHighContrast
                implicitWidth: Config.controls.popup["normal"].background.width
                implicitHeight: Config.controls.popup["normal"].background.height
                color: control.palette.window
                border.color: control.palette.text
                radius: 4
            }
        }
    }
}
