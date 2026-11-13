import QtQuick
import QtQuick.Controls
import QtQuick.Layouts
import QtQuick.Controls.Material

import org.electrum 1.0

import "controls"

Pane {
    id: root
    objectName: 'Console'

    property string title: qsTr('Console')

    padding: 0

    property var _completions: undefined

    function runCommand() {
        root._completions = undefined
        PyConsole.runCommand(cmdField.text)
        cmdField.text = ''
    }

    function complete() {
        var result = PyConsole.getCompletions(cmdField.text)
        cmdField.text = result.text
        cmdField.cursorPosition = cmdField.text.length
        root._completions = result.candidates.length > 0 ? result : undefined
    }

    function setCommand(text) {
        cmdField.text = text
        cmdField.cursorPosition = text.length
    }

    ColumnLayout {
        anchors.fill: parent
        spacing: 0

        Flickable {
            id: outputFlickable
            Layout.fillWidth: true
            Layout.fillHeight: true
            Layout.leftMargin: constants.paddingXSmall
            Layout.rightMargin: constants.paddingXSmall
            clip: true
            boundsBehavior: Flickable.StopAtBounds

            function scrollToEnd() {
                if (contentHeight > height)
                    contentY = contentHeight - height
                else
                    contentY = 0
            }

            TextArea.flickable: TextArea {
                id: outputText
                text: PyConsole.output
                readOnly: true
                font.family: FixedFont
                font.pixelSize: constants.fontSizeSmall
                wrapMode: TextEdit.WrapAnywhere
                textFormat: TextEdit.PlainText
            }

            ScrollBar.vertical: ScrollBar { }

            Connections {
                target: PyConsole
                function onOutputChanged() {
                    Qt.callLater(outputFlickable.scrollToEnd)
                }
            }
        }

        Flickable {
            id: completionsBar
            Layout.fillWidth: true
            Layout.leftMargin: constants.paddingSmall
            Layout.rightMargin: constants.paddingSmall
            visible: root._completions !== undefined
            implicitHeight: completionsRow.height
            contentWidth: completionsRow.width
            clip: true
            flickableDirection: Flickable.HorizontalFlick

            Row {
                id: completionsRow
                spacing: constants.paddingXSmall

                Repeater {
                    model: root._completions !== undefined ? root._completions.candidates : []

                    Button {
                        // no button in the console takes focus, so tapping one leaves the keyboard as it is
                        focusPolicy: Qt.NoFocus
                        text: modelData.split('.').pop()
                        font.family: FixedFont
                        font.pixelSize: constants.fontSizeSmall
                        onClicked: {
                            root.setCommand(root._completions.beginning + modelData)
                            root._completions = undefined
                        }
                    }
                }
            }
        }

        RowLayout {
            id: inputRow
            Layout.fillWidth: true
            // the completion buttons' bottom inset already leaves a gap
            Layout.topMargin: completionsBar.visible ? 0 : constants.paddingXSmall
            Layout.bottomMargin: constants.paddingXSmall
            Layout.leftMargin: constants.paddingMedium
            Layout.rightMargin: constants.paddingMedium
            spacing: constants.paddingXSmall

            Label {
                text: PyConsole.prompt
                font.family: FixedFont
                font.pixelSize: constants.fontSizeMedium
                color: Material.accentColor
            }

            TextField {
                id: cmdField
                Layout.fillWidth: true
                font.family: FixedFont
                font.pixelSize: constants.fontSizeMedium
                inputMethodHints: Qt.ImhNoPredictiveText | Qt.ImhSensitiveData | Qt.ImhNoAutoUppercase
                onAccepted: root.runCommand()
            }

            ToolButton {
                focusPolicy: Qt.NoFocus
                icon.source: '../../icons/closebutton.png'
                icon.color: constants.colorError
                visible: PyConsole.inConstruct
                onClicked: PyConsole.keyboardInterrupt()
            }
        }

        ButtonContainer {
            Layout.fillWidth: true

            FlatButton {
                focusPolicy: Qt.NoFocus
                Layout.fillWidth: true
                Layout.preferredWidth: 1
                text: '▲'
                onClicked: root.setCommand(PyConsole.getPrevHistoryEntry())
            }
            FlatButton {
                focusPolicy: Qt.NoFocus
                Layout.fillWidth: true
                Layout.preferredWidth: 1
                text: '▼'
                onClicked: root.setCommand(PyConsole.getNextHistoryEntry())
            }
            FlatButton {
                focusPolicy: Qt.NoFocus
                Layout.fillWidth: true
                Layout.preferredWidth: 1
                text: qsTr('Tab')
                onClicked: root.complete()
            }
            FlatButton {
                focusPolicy: Qt.NoFocus
                Layout.fillWidth: true
                Layout.preferredWidth: 1
                icon.source: '../../icons/tab_send.png'
                text: qsTr('Run')
                onClicked: root.runCommand()
            }
        }
    }

    // covers the command input and buttons (and blocks presses) until the warning is dismissed
    Pane {
        id: warningOverlay
        anchors.left: parent.left
        anchors.right: parent.right
        anchors.bottom: parent.bottom
        height: Math.max(implicitHeight, parent.height - inputRow.y)
        padding: constants.paddingMedium

        InfoTextArea {
            width: parent.width
            anchors.verticalCenter: parent.verticalCenter
            compact: true
            iconStyle: InfoTextArea.IconStyle.Warn
            textFormat: Text.RichText
            text: '<b>' + qsTr('Warning!') + '</b><br>'
                + qsTr("Do not paste code here that you don't understand. Executing the wrong code could lead to your coins being irreversibly lost.")
                + '<br>' + qsTr('Tap here to hide this message.')

            // not a MouseArea: a second child item stops the Pane from sizing to its content
            TapHandler {
                onTapped: warningOverlay.visible = false
            }
        }
    }

    property color navigationBarBackgroundColor: constants.highlightBackground
}
