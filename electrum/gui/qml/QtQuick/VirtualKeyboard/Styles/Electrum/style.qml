/****************************************************************************
**
** Copyright (C) 2016 The Qt Company Ltd.
** Contact: https://www.qt.io/licensing/
**
** This file is part of the Qt Virtual Keyboard module of the Qt Toolkit.
**
** $QT_BEGIN_LICENSE:GPL$
** Commercial License Usage
** Licensees holding valid commercial Qt licenses may use this file in
** accordance with the commercial license agreement provided with the
** Software or, alternatively, in accordance with the terms contained in
** a written agreement between you and The Qt Company. For licensing terms
** and conditions see https://www.qt.io/terms-conditions. For further
** information use the contact form at https://www.qt.io/contact-us.
**
** GNU General Public License Usage
** Alternatively, this file may be used under the terms of the GNU
** General Public License version 3 or (at your option) any later version
** approved by the KDE Free Qt Foundation. The licenses are as published by
** the Free Software Foundation and appearing in the file LICENSE.GPL3
** included in the packaging of this file. Please review the following
** information to ensure the GNU General Public License requirements will
** be met: https://www.gnu.org/licenses/gpl-3.0.html.
**
** $QT_END_LICENSE$
**
****************************************************************************/

import QtQuick 2.7
import QtQuick.VirtualKeyboard 2.1
import QtQuick.VirtualKeyboard.Styles 2.1

import QtQuick.Controls.Material 2.0

KeyboardStyle {
    id: currentStyle

    readonly property bool compactSelectionList: [InputEngine.InputMode.Pinyin, InputEngine.InputMode.Cangjie, InputEngine.InputMode.Zhuyin].indexOf(InputContext.inputEngine.inputMode) !== -1
    readonly property string fontFamily: "Sans"
    readonly property real keyBackgroundMargin: Math.round(13 * scaleHint)
    readonly property real keyContentMargin: Math.round(45 * scaleHint)
    readonly property real keyIconScale: scaleHint * 0.6
    readonly property string resourcePrefix: ''

    readonly property string inputLocale: InputContext.locale
    property color inputLocaleIndicatorColor: "white"
    property Timer inputLocaleIndicatorHighlightTimer: Timer {
        interval: 1000
        onTriggered: inputLocaleIndicatorColor = "gray"
    }
    onInputLocaleChanged: {
        inputLocaleIndicatorColor = 'red' //"white"
        inputLocaleIndicatorHighlightTimer.restart()
    }

    keyboardDesignWidth: 2560
    keyboardDesignHeight: 1440
    keyboardRelativeLeftMargin: 114 / keyboardDesignWidth
    keyboardRelativeRightMargin: 114 / keyboardDesignWidth
    keyboardRelativeTopMargin: 13 / keyboardDesignHeight
    keyboardRelativeBottomMargin: 86 / keyboardDesignHeight

    keyboardBackground: Rectangle {
        color: constants.colorAlpha(Material.accentColor, 0.5) //mutedForeground //'red' //"black"
    }

    keyPanel: ElectrumKeyPanel {
        id: keyPanel
        Rectangle {
            id: keyBackground
            radius: 5
            color: "#383533"
            anchors.fill: keyPanel
            anchors.margins: keyBackgroundMargin
            Text {
                id: keySmallText
                text: control.smallText
                visible: control.smallTextVisible
                color: "gray"
                anchors.right: parent.right
                anchors.top: parent.top
                anchors.margins: keyContentMargin / 3
                font {
                    family: fontFamily
                    weight: Font.Normal
                    pixelSize: 38 * scaleHint * 2
                    capitalization: control.uppercased ? Font.AllUppercase : Font.MixedCase
                }
            }
            Text {
                id: keyText
                text: control.displayText
                color: "white"
                horizontalAlignment: Text.AlignHCenter
                verticalAlignment: Text.AlignVCenter
                anchors.fill: parent
                anchors.leftMargin: keyContentMargin
                anchors.topMargin: keyContentMargin
                anchors.rightMargin: keyContentMargin
                anchors.bottomMargin: keyContentMargin
                font {
                    family: fontFamily
                    weight: Font.Normal
                    pixelSize: 52 * scaleHint * 2
                    capitalization: control.uppercased ? Font.AllUppercase : Font.MixedCase
                }
            }
        }
        states: [
            State {
                name: "pressed"
                when: control.pressed
                PropertyChanges {
                    target: keyBackground
                    opacity: 0.75
                }
                PropertyChanges {
                    target: keyText
                    opacity: 0.5
                }
            },
            State {
                name: "disabled"
                when: !control.enabled
                PropertyChanges {
                    target: keyBackground
                    opacity: 0.75
                }
                PropertyChanges {
                    target: keyText
                    opacity: 0.05
                }
            }
        ]
    }

    backspaceKeyPanel: ElectrumKeyPanel {
        id: backspaceKeyPanel
        Rectangle {
            id: backspaceKeyBackground
            radius: 5
            color: "#23211E"
            anchors.fill: backspaceKeyPanel
            anchors.margins: keyBackgroundMargin
            Image {
                id: backspaceKeyIcon
                anchors.centerIn: parent
                sourceSize.width: 159 * keyIconScale
                sourceSize.height: 88 * keyIconScale
                smooth: false
                source: resourcePrefix + "images/backspace-868482.svg"
            }
        }
        states: [
            State {
                name: "pressed"
                when: control.pressed
                PropertyChanges {
                    target: backspaceKeyBackground
                    opacity: 0.80
                }
                PropertyChanges {
                    target: backspaceKeyIcon
                    opacity: 0.6
                }
            },
            State {
                name: "disabled"
                when: !control.enabled
                PropertyChanges {
                    target: backspaceKeyBackground
                    opacity: 0.8
                }
                PropertyChanges {
                    target: backspaceKeyIcon
                    opacity: 0.2
                }
            }
        ]
    }

    languageKeyPanel: ElectrumKeyPanel {
        id: languageKeyPanel
        Rectangle {
            id: languageKeyBackground
            radius: 5
            color: "#35322f"
            anchors.fill: languageKeyPanel
            anchors.margins: keyBackgroundMargin
            Image {
                id: languageKeyIcon
                anchors.centerIn: parent
                sourceSize.width: 144 * keyIconScale
                sourceSize.height: 144 * keyIconScale
                smooth: false
                source: resourcePrefix + "images/globe-868482.svg"
            }
        }
        states: [
            State {
                name: "pressed"
                when: control.pressed
                PropertyChanges {
                    target: languageKeyBackground
                    opacity: 0.80
                }
                PropertyChanges {
                    target: languageKeyIcon
                    opacity: 0.75
                }
            },
            State {
                name: "disabled"
                when: !control.enabled
                PropertyChanges {
                    target: languageKeyBackground
                    opacity: 0.8
                }
                PropertyChanges {
                    target: languageKeyIcon
                    opacity: 0.2
                }
            }
        ]
    }

    enterKeyPanel: ElectrumKeyPanel {
        id: enterKeyPanel
        Rectangle {
            id: enterKeyBackground
            radius: 5
            color: "#1e1b18"
            anchors.fill: enterKeyPanel
            anchors.margins: keyBackgroundMargin
            Image {
                id: enterKeyIcon
                visible: enterKeyText.text.length === 0
                anchors.centerIn: parent
                readonly property size enterKeyIconSize: {
                    switch (control.actionId) {
                    case EnterKeyAction.Go:
                    case EnterKeyAction.Send:
                    case EnterKeyAction.Next:
                    case EnterKeyAction.Done:
                        return Qt.size(170, 119)
                    case EnterKeyAction.Search:
                        return Qt.size(148, 148)
                    default:
                        return Qt.size(211, 80)
                    }
                }
                sourceSize.width: enterKeyIconSize.width * keyIconScale
                sourceSize.height: enterKeyIconSize.height * keyIconScale
                smooth: false
                source: {
                    switch (control.actionId) {
                    case EnterKeyAction.Go:
                    case EnterKeyAction.Send:
                    case EnterKeyAction.Next:
                    case EnterKeyAction.Done:
                        return resourcePrefix + "images/check-868482.svg"
                    case EnterKeyAction.Search:
                        return resourcePrefix + "images/search-868482.svg"
                    default:
                        return resourcePrefix + "images/enter-868482.svg"
                    }
                }
            }
            Text {
                id: enterKeyText
                visible: text.length !== 0
                text: control.actionId !== EnterKeyAction.None ? control.displayText : ""
                clip: true
                fontSizeMode: Text.HorizontalFit
                horizontalAlignment: Text.AlignHCenter
                verticalAlignment: Text.AlignVCenter
                color: "#80c342"
                font {
                    family: fontFamily
                    weight: Font.Normal
                    pixelSize: 44 * scaleHint
                    capitalization: Font.AllUppercase
                }
                anchors.fill: parent
                anchors.margins: Math.round(42 * scaleHint)
            }
        }
        states: [
            State {
                name: "pressed"
                when: control.pressed
                PropertyChanges {
                    target: enterKeyBackground
                    opacity: 0.80
                }
                PropertyChanges {
                    target: enterKeyIcon
                    opacity: 0.6
                }
                PropertyChanges {
                    target: enterKeyText
                    opacity: 0.6
                }
            },
            State {
                name: "disabled"
                when: !control.enabled
                PropertyChanges {
                    target: enterKeyBackground
                    opacity: 0.8
                }
                PropertyChanges {
                    target: enterKeyIcon
                    opacity: 0.2
                }
                PropertyChanges {
                    target: enterKeyText
                    opacity: 0.2
                }
            }
        ]
    }

    hideKeyPanel: ElectrumKeyPanel {
        id: hideKeyPanel
        Rectangle {
            id: hideKeyBackground
            radius: 5
            color: "#1e1b18"
            anchors.fill: hideKeyPanel
            anchors.margins: keyBackgroundMargin
            Image {
                id: hideKeyIcon
                anchors.centerIn: parent
                sourceSize.width: 144 * keyIconScale
                sourceSize.height: 127 * keyIconScale
                smooth: false
                source: resourcePrefix + "images/hidekeyboard-868482.svg"
            }
        }
        states: [
            State {
                name: "pressed"
                when: control.pressed
                PropertyChanges {
                    target: hideKeyBackground
                    opacity: 0.80
                }
                PropertyChanges {
                    target: hideKeyIcon
                    opacity: 0.6
                }
            },
            State {
                name: "disabled"
                when: !control.enabled
                PropertyChanges {
                    target: hideKeyBackground
                    opacity: 0.8
                }
                PropertyChanges {
                    target: hideKeyIcon
                    opacity: 0.2
                }
            }
        ]
    }

    shiftKeyPanel: ElectrumKeyPanel {
        id: shiftKeyPanel
        Rectangle {
            id: shiftKeyBackground
            radius: 5
            color: "#1e1b18"
            anchors.fill: shiftKeyPanel
            anchors.margins: keyBackgroundMargin
            Image {
                id: shiftKeyIcon
                anchors.centerIn: parent
                sourceSize.width: 144 * keyIconScale
                sourceSize.height: 134 * keyIconScale
                smooth: false
                source: resourcePrefix + "images/shift-868482.svg"
            }
            states: [
                State {
                    name: "capsLockActive"
                    when: InputContext.capsLockActive
                    PropertyChanges {
                        target: shiftKeyBackground
                        color: "#5a892e"
                    }
                    PropertyChanges {
                        target: shiftKeyIcon
                        source: resourcePrefix + "images/shift-c5d6b6.svg"
                    }
                },
                State {
                    name: "shiftActive"
                    when: InputContext.shiftActive
                    PropertyChanges {
                        target: shiftKeyIcon
                        source: resourcePrefix + "images/shift-80c342.svg"
                    }
                }
            ]
        }
        states: [
            State {
                name: "pressed"
                when: control.pressed
                PropertyChanges {
                    target: shiftKeyBackground
                    opacity: 0.80
                }
                PropertyChanges {
                    target: shiftKeyIcon
                    opacity: 0.6
                }
            },
            State {
                name: "disabled"
                when: !control.enabled
                PropertyChanges {
                    target: shiftKeyBackground
                    opacity: 0.8
                }
                PropertyChanges {
                    target: shiftKeyIcon
                    opacity: 0.2
                }
            }
        ]
    }

    spaceKeyPanel: ElectrumKeyPanel {
        id: spaceKeyPanel
        Rectangle {
            id: spaceKeyBackground
            radius: 5
            color: "#35322f"
            anchors.fill: spaceKeyPanel
            anchors.margins: keyBackgroundMargin
            Text {
                id: spaceKeyText
                text: Qt.locale(InputContext.locale).nativeLanguageName
                color: currentStyle.inputLocaleIndicatorColor
                Behavior on color { PropertyAnimation { duration: 250 } }
                anchors.centerIn: parent
                font {
                    family: fontFamily
                    weight: Font.Normal
                    pixelSize: 48 * scaleHint * 1.5
                }
            }
        }
        states: [
            State {
                name: "pressed"
                when: control.pressed
                PropertyChanges {
                    target: spaceKeyBackground
                    opacity: 0.80
                }
            },
            State {
                name: "disabled"
                when: !control.enabled
                PropertyChanges {
                    target: spaceKeyBackground
                    opacity: 0.8
                }
            }
        ]
    }

    symbolKeyPanel: ElectrumKeyPanel {
        id: symbolKeyPanel
        Rectangle {
            id: symbolKeyBackground
            radius: 5
            color: "#1e1b18"
            anchors.fill: symbolKeyPanel
            anchors.margins: keyBackgroundMargin
            Text {
                id: symbolKeyText
                text: control.displayText
                color: "white"
                horizontalAlignment: Text.AlignHCenter
                verticalAlignment: Text.AlignVCenter
                anchors.fill: parent
                anchors.margins: keyContentMargin
                font {
                    family: fontFamily
                    weight: Font.Normal
                    pixelSize: 44 * scaleHint * 2
                    capitalization: Font.AllUppercase
                }
            }
        }
        states: [
            State {
                name: "pressed"
                when: control.pressed
                PropertyChanges {
                    target: symbolKeyBackground
                    opacity: 0.80
                }
                PropertyChanges {
                    target: symbolKeyText
                    opacity: 0.6
                }
            },
            State {
                name: "disabled"
                when: !control.enabled
                PropertyChanges {
                    target: symbolKeyBackground
                    opacity: 0.8
                }
                PropertyChanges {
                    target: symbolKeyText
                    opacity: 0.2
                }
            }
        ]
    }

    modeKeyPanel: ElectrumKeyPanel {
        id: modeKeyPanel
        Rectangle {
            id: modeKeyBackground
            radius: 5
            color: "#1e1b18"
            anchors.fill: modeKeyPanel
            anchors.margins: keyBackgroundMargin
            Text {
                id: modeKeyText
                text: control.displayText
                color: "white"
                horizontalAlignment: Text.AlignHCenter
                verticalAlignment: Text.AlignVCenter
                anchors.fill: parent
                anchors.margins: keyContentMargin
                font {
                    family: fontFamily
                    weight: Font.Normal
                    pixelSize: 44 * scaleHint
                    capitalization: Font.AllUppercase
                }
            }
            Rectangle {
                id: modeKeyIndicator
                implicitHeight: parent.height * 0.1
                anchors.left: parent.left
                anchors.right: parent.right
                anchors.bottom: parent.bottom
                anchors.leftMargin: parent.width * 0.4
                anchors.rightMargin: parent.width * 0.4
                anchors.bottomMargin: parent.height * 0.12
                color: "#80c342"
                radius: 3
                visible: control.mode
            }
        }
        states: [
            State {
                name: "pressed"
                when: control.pressed
                PropertyChanges {
                    target: modeKeyBackground
                    opacity: 0.80
                }
                PropertyChanges {
                    target: modeKeyText
                    opacity: 0.6
                }
            },
            State {
                name: "disabled"
                when: !control.enabled
                PropertyChanges {
                    target: modeKeyBackground
                    opacity: 0.8
                }
                PropertyChanges {
                    target: modeKeyText
                    opacity: 0.2
                }
            }
        ]
    }

    handwritingKeyPanel: ElectrumKeyPanel {
        id: handwritingKeyPanel
        Rectangle {
            id: hwrKeyBackground
            radius: 5
            color: "#35322f"
            anchors.fill: handwritingKeyPanel
            anchors.margins: keyBackgroundMargin
            Image {
                id: hwrKeyIcon
                anchors.centerIn: parent
                readonly property size hwrKeyIconSize: keyboard.handwritingMode ? Qt.size(124, 96) : Qt.size(156, 104)
                sourceSize.width: hwrKeyIconSize.width * keyIconScale
                sourceSize.height: hwrKeyIconSize.height * keyIconScale
                smooth: false
                source: resourcePrefix + (keyboard.handwritingMode ? "images/textmode-868482.svg" : "images/handwriting-868482.svg")
            }
        }
        states: [
            State {
                name: "pressed"
                when: control.pressed
                PropertyChanges {
                    target: hwrKeyBackground
                    opacity: 0.80
                }
                PropertyChanges {
                    target: hwrKeyIcon
                    opacity: 0.6
                }
            },
            State {
                name: "disabled"
                when: !control.enabled
                PropertyChanges {
                    target: hwrKeyBackground
                    opacity: 0.8
                }
                PropertyChanges {
                    target: hwrKeyIcon
                    opacity: 0.2
                }
            }
        ]
    }

    characterPreviewMargin: 0
    characterPreviewDelegate: Item {
        property string text
        id: characterPreview
        Rectangle {
            id: characterPreviewBackground
            anchors.fill: parent
            color: "#5d5b59"
            radius: 5
            Text {
                id: characterPreviewText
                color: "white"
                text: characterPreview.text
                fontSizeMode: Text.HorizontalFit
                horizontalAlignment: Text.AlignHCenter
                verticalAlignment: Text.AlignVCenter
                anchors.fill: parent
                anchors.margins: Math.round(48 * scaleHint)
                font {
                    family: fontFamily
                    weight: Font.Normal
                    pixelSize: 82 * scaleHint * 2
                }
            }
        }
    }

    alternateKeysListItemWidth: 99 * scaleHint * 2
    alternateKeysListItemHeight: 150 * scaleHint * 2
    alternateKeysListDelegate: Item {
        id: alternateKeysListItem
        width: alternateKeysListItemWidth
        height: alternateKeysListItemHeight
        Text {
            id: listItemText
            text: model.text
            color: "#868482"
            font {
                family: fontFamily
                weight: Font.Normal
                pixelSize: 52 * scaleHint * 2
            }
            anchors.centerIn: parent
        }
        states: State {
            name: "current"
            when: alternateKeysListItem.ListView.isCurrentItem
            PropertyChanges {
                target: listItemText
                color: "white"
            }
        }
    }
    alternateKeysListHighlight: Rectangle {
        color: "#5d5b59"
        radius: 5
    }
    alternateKeysListBackground: Rectangle {
        color: "#1e1b18"
        radius: 5
    }

    selectionListHeight: 85 * scaleHint * 2
    selectionListDelegate: SelectionListItem {
        id: selectionListItem
        width: Math.round(selectionListLabel.width + selectionListLabel.anchors.leftMargin * 2)
        Text {
            id: selectionListLabel
            anchors.left: parent.left
            anchors.leftMargin: Math.round((compactSelectionList ? 50 : 140) * scaleHint)
            anchors.verticalCenter: parent.verticalCenter
            text: decorateText(display, wordCompletionLength)
            color: "#80c342"
            font {
                family: fontFamily
                weight: Font.Normal
                pixelSize: 44 * scaleHint * 2
            }
            function decorateText(text, wordCompletionLength) {
                if (wordCompletionLength > 0) {
                    return text.slice(0, -wordCompletionLength) + '<u>' + text.slice(-wordCompletionLength) + '</u>'
                }
                return text
            }
        }
        Rectangle {
            id: selectionListSeparator
            width: 4 * scaleHint
            height: 36 * scaleHint
            radius: 2
            color: "#35322f"
            anchors.verticalCenter: parent.verticalCenter
            anchors.right: parent.left
        }
        states: State {
            name: "current"
            when: selectionListItem.ListView.isCurrentItem
            PropertyChanges {
                target: selectionListLabel
                color: "white"
            }
        }
    }
    selectionListBackground: Rectangle {
        color: "#1e1b18"
    }
    selectionListAdd: Transition {
        NumberAnimation { property: "y"; from: wordCandidateView.height; duration: 200 }
        NumberAnimation { property: "opacity"; from: 0; to: 1; duration: 200 }
    }
    selectionListRemove: Transition {
        NumberAnimation { property: "y"; to: -wordCandidateView.height; duration: 200 }
        NumberAnimation { property: "opacity"; to: 0; duration: 200 }
    }

    navigationHighlight: Rectangle {
        color: "transparent"
        border.color: "yellow"
        border.width: 5
    }

    traceInputKeyPanelDelegate: TraceInputKeyPanel {
        id: traceInputKeyPanel
        traceMargins: keyBackgroundMargin
        Rectangle {
            id: traceInputKeyPanelBackground
            radius: 5
            color: "#35322f"
            anchors.fill: traceInputKeyPanel
            anchors.margins: keyBackgroundMargin
            Text {
                id: hwrInputModeIndicator
                visible: control.patternRecognitionMode === InputEngine.PatternRecognitionMode.Handwriting
                text: {
                    switch (InputContext.inputEngine.inputMode) {
                    case InputEngine.InputMode.Numeric:
                        if (["ar", "fa"].indexOf(InputContext.locale.substring(0, 2)) !== -1)
                            return "\u0660\u0661\u0662"
                        // Fallthrough
                    case InputEngine.InputMode.Dialable:
                        return "123"
                    case InputEngine.InputMode.Greek:
                        return "ΑΒΓ"
                    case InputEngine.InputMode.Cyrillic:
                        return "АБВ"
                    case InputEngine.InputMode.Arabic:
                        if (InputContext.locale.substring(0, 2) === "fa")
                            return "\u0627\u200C\u0628\u200C\u067E"
                        return "\u0623\u200C\u0628\u200C\u062C"
                    case InputEngine.InputMode.Hebrew:
                        return "\u05D0\u05D1\u05D2"
                    case InputEngine.InputMode.ChineseHandwriting:
                        return "中文"
                    case InputEngine.InputMode.JapaneseHandwriting:
                        return "日本語"
                    case InputEngine.InputMode.KoreanHandwriting:
                        return "한국어"
                    case InputEngine.InputMode.Thai:
                        return "กขค"
                    default:
                        return "Abc"
                    }
                }
                color: "white"
                anchors.left: parent.left
                anchors.top: parent.top
                anchors.margins: keyContentMargin
                font {
                    family: fontFamily
                    weight: Font.Normal
                    pixelSize: 44 * scaleHint
                    capitalization: {
                        if (InputContext.capsLockActive)
                            return Font.AllUppercase
                        if (InputContext.shiftActive)
                            return Font.MixedCase
                        return Font.AllLowercase
                    }
                }
            }
        }
        Canvas {
            id: traceInputKeyGuideLines
            anchors.fill: traceInputKeyPanelBackground
            opacity: 0.1
            onPaint: {
                var ctx = getContext("2d")
                ctx.lineWidth = 1
                ctx.strokeStyle = Qt.rgba(0xFF, 0xFF, 0xFF)
                ctx.clearRect(0, 0, width, height)
                var i
                var margin = Math.round(30 * scaleHint)
                if (control.horizontalRulers) {
                    for (i = 0; i < control.horizontalRulers.length; i++) {
                        ctx.beginPath()
                        var y = Math.round(control.horizontalRulers[i])
                        var rightMargin = Math.round(width - margin)
                        if (i + 1 === control.horizontalRulers.length) {
                            ctx.moveTo(margin, y)
                            ctx.lineTo(rightMargin, y)
                        } else {
                            var dashLen = Math.round(20 * scaleHint)
                            for (var dash = margin, dashCount = 0;
                                 dash < rightMargin; dash += dashLen, dashCount++) {
                                if ((dashCount & 1) === 0) {
                                    ctx.moveTo(dash, y)
                                    ctx.lineTo(Math.min(dash + dashLen, rightMargin), y)
                                }
                            }
                        }
                        ctx.stroke()
                    }
                }
                if (control.verticalRulers) {
                    for (i = 0; i < control.verticalRulers.length; i++) {
                        ctx.beginPath()
                        ctx.moveTo(control.verticalRulers[i], margin)
                        ctx.lineTo(control.verticalRulers[i], Math.round(height - margin))
                        ctx.stroke()
                    }
                }
            }
            Connections {
                target: control
                onHorizontalRulersChanged: traceInputKeyGuideLines.requestPaint()
                onVerticalRulersChanged: traceInputKeyGuideLines.requestPaint()
            }
        }
    }

    traceCanvasDelegate: TraceCanvas {
        id: traceCanvas
        onAvailableChanged: {
            if (!available)
                return
            var ctx = getContext("2d")
            if (parent.canvasType === "fullscreen") {
                ctx.lineWidth = 10
                ctx.strokeStyle = Qt.rgba(0, 0, 0)
            } else {
                ctx.lineWidth = 10 * scaleHint
                ctx.strokeStyle = Qt.rgba(0xFF, 0xFF, 0xFF)
            }
            ctx.lineCap = "round"
            ctx.fillStyle = ctx.strokeStyle
        }
        autoDestroyDelay: 800
        onTraceChanged: if (trace === null) opacity = 0
        Behavior on opacity { PropertyAnimation { easing.type: Easing.OutCubic; duration: 150 } }
    }

    popupListDelegate: SelectionListItem {
        property real cursorAnchor: popupListLabel.x + popupListLabel.width
        id: popupListItem
        width: popupListLabel.width + popupListLabel.anchors.leftMargin * 2
        height: popupListLabel.height + popupListLabel.anchors.topMargin * 2
        Text {
            id: popupListLabel
            anchors.left: parent.left
            anchors.top: parent.top
            anchors.leftMargin: popupListLabel.height / 2
            anchors.topMargin: popupListLabel.height / 3
            text: decorateText(display, wordCompletionLength)
            color: "#5CAA15"
            font {
                family: fontFamily
                weight: Font.Normal
                pixelSize: Qt.inputMethod.cursorRectangle.height * 0.8
            }
            function decorateText(text, wordCompletionLength) {
                if (wordCompletionLength > 0) {
                    return text.slice(0, -wordCompletionLength) + '<u>' + text.slice(-wordCompletionLength) + '</u>'
                }
                return text
            }
        }
        states: State {
            name: "current"
            when: popupListItem.ListView.isCurrentItem
            PropertyChanges {
                target: popupListLabel
                color: "black"
            }
        }
    }

    popupListBackground: Item {
        Rectangle {
            width: parent.width
            height: parent.height
            color: "white"
            border {
                width: 1
                color: "#929495"
            }
        }
    }

    popupListAdd: Transition {
        NumberAnimation { property: "opacity"; from: 0; to: 1.0; duration: 200 }
    }

    popupListRemove: Transition {
        NumberAnimation { property: "opacity"; to: 0; duration: 200 }
    }

    languagePopupListEnabled: true

    languageListDelegate: SelectionListItem {
        id: languageListItem
        width: languageNameTextMetrics.width * 17
        height: languageNameTextMetrics.height + languageListLabel.anchors.topMargin + languageListLabel.anchors.bottomMargin
        Text {
            id: languageListLabel
            anchors.left: parent.left
            anchors.top: parent.top
            anchors.leftMargin: languageNameTextMetrics.height / 2
            anchors.rightMargin: anchors.leftMargin
            anchors.topMargin: languageNameTextMetrics.height / 3
            anchors.bottomMargin: anchors.topMargin
            text: languageNameFormatter.elidedText
            // color: "#5CAA15"
            color: constants.mutedForeground
            font {
                family: fontFamily
                weight: Font.Normal
                pixelSize: 44 * scaleHint * 2
            }
        }
        TextMetrics {
            id: languageNameTextMetrics
            font {
                family: fontFamily
                weight: Font.Normal
                pixelSize: 44 * scaleHint * 2
            }
            text: "X"
        }
        TextMetrics {
            id: languageNameFormatter
            font {
                family: fontFamily
                weight: Font.Normal
                pixelSize: 44 * scaleHint * 2
            }
            elide: Text.ElideRight
            elideWidth: languageListItem.width - languageListLabel.anchors.leftMargin - languageListLabel.anchors.rightMargin
            text: displayName
        }
        states: State {
            name: "current"
            when: languageListItem.ListView.isCurrentItem
            PropertyChanges {
                target: languageListLabel
                color: 'white'
            }
        }
    }

    languageListBackground: Rectangle {
        color: constants.lighterBackground

        border {
            width: 1
            color: "#929495"
        }
    }

    languageListAdd: Transition {
        NumberAnimation { property: "opacity"; from: 0; to: 1.0; duration: 200 }
    }

    languageListRemove: Transition {
        NumberAnimation { property: "opacity"; to: 0; duration: 200 }
    }

    selectionHandle: Image {
        sourceSize.width: 20
        source: resourcePrefix + "images/selectionhandle-bottom.svg"
    }

    fullScreenInputContainerBackground: Rectangle {
        color: "#FFF"
    }

    fullScreenInputBackground: Rectangle {
        color: "#FFF"
    }

    fullScreenInputMargins: Math.round(15 * scaleHint)

    fullScreenInputPadding: Math.round(30 * scaleHint)

    fullScreenInputCursor: Rectangle {
        width: 1
        color: "#000"
        visible: parent.blinkStatus
    }

    fullScreenInputFont.pixelSize: 58 * scaleHint
}
