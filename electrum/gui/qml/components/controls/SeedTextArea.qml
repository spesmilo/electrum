import QtQuick
import QtQuick.Layouts
import QtQuick.Controls
import QtQuick.Controls.Material

import org.electrum 1.0

Pane {
    id: root
    implicitHeight: rootLayout.height
    padding: 0

    property string text
    property bool readOnly: false
    property alias placeholderText: seedtextarea.placeholderText
    property string indicatorText
    property bool indicatorValid

    property var _suggestions: []

    onTextChanged: {
        if (seedtextarea.text != text)
            seedtextarea.text = text
    }

    background: Rectangle {
        color: "transparent"
    }

    ColumnLayout {
        id: rootLayout
        width: parent.width
        spacing: 0

        TextArea {
            id: seedtextarea
            Layout.fillWidth: true
            Layout.minimumHeight: fontMetrics.lineSpacing * 3 + topPadding + bottomPadding

            rightPadding: constants.paddingLarge
            leftPadding: constants.paddingLarge
            bottomPadding: constants.paddingXLarge

            wrapMode: TextInput.WordWrap
            font.bold: true
            font.pixelSize: constants.fontSizeLarge
            font.family: FixedFont
            inputMethodHints: Qt.ImhSensitiveData | Qt.ImhLowercaseOnly | Qt.ImhNoPredictiveText
            readOnly: AppController.isAndroid()

            Component.onCompleted: {
                background.filled = true
                background.fillColor = constants.seedTextAreaBackground
            }

            onTextChanged: {
                // work around Qt issue, TextArea fires spurious textChanged events
                // NOTE: might be Qt virtual keyboard, or Qt upgrade from 5.15.2 to 5.15.7
                if (root.text != text)
                    root.text = text

                // update suggestions
                _suggestions = bitcoin.mnemonicsFor(seedtextarea.text.split(' ').pop())
                // TODO: cursorPosition only on suggestion apply
                cursorPosition = text.length
            }

            Rectangle {
                anchors.fill: contentText
                color: root.indicatorValid ? 'green' : 'red'
                radius: 3
            }
            Label {
                id: contentText
                text: root.indicatorText
                anchors.right: parent.right
                anchors.bottom: parent.bottom
                anchors.rightMargin: constants.paddingXXSmall
                anchors.bottomMargin: constants.paddingXXSmall
                leftPadding: root.indicatorText != '' ? constants.paddingMedium : 0
                rightPadding: root.indicatorText != '' ? constants.paddingMedium : 0
                topPadding: root.indicatorText != '' ? constants.paddingXXSmall/2 : 0
                bottomPadding: root.indicatorText != '' ? constants.paddingXXSmall/2 : 0
                font.bold: false
                font.pixelSize: constants.fontSizeSmall
            }
        }

        Flickable {
            Layout.preferredWidth: parent.width
            Layout.minimumHeight: fontMetrics.lineSpacing + 2*constants.paddingXXSmall + 2*constants.paddingXSmall + 2
            implicitHeight: wordsLayout.height

            visible: !readOnly
            flickableDirection: Flickable.HorizontalFlick
            contentWidth: wordsLayout.width
            interactive: wordsLayout.width > width

            RowLayout {
                id: wordsLayout
                Repeater {
                    model: _suggestions
                    Rectangle {
                        Layout.margins: constants.paddingXXSmall
                        width: suggestionLabel.width
                        height: suggestionLabel.height
                        color: constants.darkerDialogBackground
                        radius: constants.paddingXXSmall
                        Label {
                            id: suggestionLabel
                            text: modelData
                            padding: constants.paddingXSmall
                            leftPadding: constants.paddingSmall
                            rightPadding: constants.paddingSmall
                        }
                        MouseArea {
                            anchors.fill: parent
                            onClicked: {
                                var words = seedtextarea.text.split(' ')
                                words.pop()
                                words.push(modelData)
                                seedtextarea.text = words.join(' ') + ' '
                            }
                        }
                    }
                }
            }
        }

        SeedKeyboard {
            id: kbd
            Layout.fillWidth: true
            Layout.preferredHeight: kbd.width / 1.75
            visible: !root.readOnly
            onKeyEvent: (keycode, text) => {
                if (keycode == Qt.Key_Backspace) {
                    if (seedtextarea.text.length > 0)
                        seedtextarea.text = seedtextarea.text.substring(0, seedtextarea.text.length-1)
                } else {
                    seedtextarea.text = seedtextarea.text + text
                }
            }
        }
    }

    FontMetrics {
        id: fontMetrics
        font: seedtextarea.font
    }

    Bitcoin {
        id: bitcoin
    }
}
