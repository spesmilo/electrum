import QtQuick 2.15
import QtQuick.Layouts 1.0
import QtQuick.Controls 2.15
import QtQuick.Controls.Material 2.0

import org.electrum 1.0

Pane {
    id: root
    implicitHeight: rootLayout.height
    padding: 0

    property string text
    property alias readOnly: seedtextarea.readOnly
    property alias placeholderText: seedtextarea.placeholderText

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
                        color: constants.lighterBackground
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

        TextArea {
            id: seedtextarea
            Layout.fillWidth: true
            Layout.minimumHeight: fontMetrics.height * 3 + topPadding + bottomPadding

            rightPadding: constants.paddingLarge
            leftPadding: constants.paddingLarge

            wrapMode: TextInput.WordWrap
            font.bold: true
            font.pixelSize: constants.fontSizeLarge
            font.family: FixedFont
            inputMethodHints: Qt.ImhSensitiveData | Qt.ImhLowercaseOnly | Qt.ImhNoPredictiveText

            background: Rectangle {
                color: constants.darkerBackground
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
