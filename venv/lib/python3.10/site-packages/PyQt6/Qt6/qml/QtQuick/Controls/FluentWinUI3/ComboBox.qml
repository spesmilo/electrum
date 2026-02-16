// Copyright (C) 2024 The Qt Company Ltd.
// SPDX-License-Identifier: LicenseRef-Qt-Commercial OR LGPL-3.0-only OR GPL-2.0-only OR GPL-3.0-only
// Qt-Security score:significant reason:default

pragma ComponentBehavior: Bound

import QtQuick
import QtQuick.Templates as T
import QtQuick.Controls.impl
import QtQuick.Controls.FluentWinUI3.impl as Impl

T.ComboBox {
    id: control

    implicitWidth: Math.max(implicitBackgroundWidth + leftInset + rightInset,
                            implicitContentWidth + leftPadding + rightPadding)
    implicitHeight: Math.max(implicitBackgroundHeight + topInset + bottomInset,
                             implicitContentHeight + topPadding + bottomPadding,
                            implicitIndicatorHeight + topPadding + bottomPadding)

    spacing: __config.contentItem.spacing || 0

    topPadding: __config.topPadding || 0
    bottomPadding: __config.bottomPadding || 0
    leftPadding: (__config.leftPadding + (!control.mirrored || !indicator || !indicator.visible ? 0 : indicator.width + spacing)) || 0
    rightPadding: (__config.rightPadding + (control.mirrored || !indicator || !indicator.visible ? 0 : indicator.width + spacing)) || 0

    topInset: -__config.topInset || 0
    bottomInset: -__config.bottomInset || 0
    leftInset: -__config.leftInset || 0
    rightInset: -__config.rightInset || 0

    readonly property string __currentState: [
        !control.enabled && "disabled",
        control.enabled && !control.pressed && control.hovered && "hovered",
        control.down && control.popup.visible && "open",
        control.pressed && "pressed"
    ].filter(Boolean).join("_") || "normal"
    readonly property var __config: (control.editable && control.down && control.popup.visible // editable combobox differs from normal one only in opened state
                                    ? Config.controls.editablecombobox[__currentState]
                                    : Config.controls.combobox[__currentState]) || {}

    readonly property Item __focusFrameTarget: control.editable ? null : control
    readonly property bool __isHighContrast: Application.styleHints.accessibility.contrastPreference === Qt.HighContrast

    delegate: ItemDelegate {
        required property var model
        required property int index

        width: ListView.view.width
        text: model[control.textRole]
        palette.highlightedText: control.palette.highlightedText
        highlighted: control.highlightedIndex === index
        hoverEnabled: control.hoverEnabled
    }

    indicator: Image {
        x: control.mirrored ? control.__config.leftPadding : control.width - width - control.__config.rightPadding
        y: (control.topPadding + (control.availableHeight - height) / 2) + (control.pressed ? 1 : 0)
        source: Qt.resolvedUrl(control.__config.indicator.filePath)

        Behavior on y {
            NumberAnimation{ easing.type: Easing.OutCubic; duration: 167 }
        }
    }

    contentItem: T.TextField {
        text: control.editable ? control.editText : control.displayText

        topPadding: control.__config.label_contentItem.topPadding || 0
        leftPadding: control.__config.label_contentItem.leftPadding || 0
        rightPadding: control.__config.label_contentItem.rightPadding || 0
        bottomPadding: control.__config.label_contentItem.bottomPadding || 0

        implicitHeight: Math.max(implicitBackgroundHeight + topInset + bottomInset,
                                 contentHeight + topPadding + bottomPadding)

        enabled: control.editable
        autoScroll: control.editable
        readOnly: control.down
        inputMethodHints: control.inputMethodHints
        validator: control.validator
        selectByMouse: control.selectTextByMouse

        readonly property color __pressedText: Application.styleHints.colorScheme == Qt.Light
                                                ? Qt.rgba(control.palette.text.r, control.palette.text.g, control.palette.text.b, 0.62)
                                                : Qt.rgba(control.palette.text.r, control.palette.text.g, control.palette.text.b, 0.7725)

        color: control.down ? __pressedText : control.palette.text
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
                visible: control.editable && ((control.down && control.popup.visible) || control.activeFocus)
                width: parent.width
                height: 2
                y: parent.height - height
                Impl.FocusStroke {
                    width: parent.width
                    height: parent.height
                    radius: control.down && control.popup.visible ? 0 : control.__config.background.bottomOffset
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
        topPadding: control.__config.popup_contentItem.topPadding || 0
        leftPadding: control.__config.popup_contentItem.leftPadding || 0
        rightPadding: control.__config.popup_contentItem.rightPadding || 0
        bottomPadding: control.__config.popup_contentItem.bottomPadding || 0

        contentItem: ListView {
            clip: true
            implicitHeight: contentHeight
            highlightMoveDuration: 0

            model: control.delegateModel
            currentIndex: control.highlightedIndex
        }

        y: control.editable ? control.height
                            : -0.25 * Math.max(implicitBackgroundHeight + topInset + bottomInset,
                                                contentHeight + topPadding + bottomPadding)
        readonly property real __targetHeight: Math.min(contentItem.implicitHeight + topPadding + bottomPadding, control.Window.height - topMargin - bottomMargin)
        property real __heightScale: 1
        height: __heightScale * __targetHeight
        width: control.width
        topMargin: 8
        bottomMargin: 8
        palette: control.palette

        enter: Transition {
            NumberAnimation { property: "__heightScale"; from: 0.33; to: 1; easing.type: Easing.OutCubic; duration: 250 }
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
