import QtQuick 2.6
import QtQuick.Layouts 1.0
import QtQuick.Controls 2.3
import QtQuick.Controls.Material 2.0

import QtQml 2.6

import "controls"

ElDialog
{
    id: root

    property var crashData

    property bool _sending: false

    width: parent.width
    height: parent.height

    header: null

    ColumnLayout {
        anchors.fill: parent
        enabled: !_sending

        Image {
            Layout.alignment: Qt.AlignCenter
            Layout.preferredWidth: 128
            Layout.preferredHeight: 128
            source: '../../icons/bug.png'
        }
        Label {
            text: qsTr('Sorry!')
            font.pixelSize: constants.fontSizeLarge
        }

        Label {
            Layout.fillWidth: true
            text: qsTr('Something went wrong while executing Electrum.')
        }
        Label {
            Layout.fillWidth: true
            text: qsTr('To help us diagnose and fix the problem, you can send us a bug report that contains useful debug information:')
            wrapMode: Text.Wrap
        }
        Button {
            Layout.alignment: Qt.AlignCenter
            text: qsTr('Show report contents')
            onClicked: {
                if (crashData.traceback)
                    console.log('traceback: ' + crashData.traceback.stack)
                var dialog = report.createObject(app, {
                    reportText: crashData.reportstring
                })
                dialog.open()
            }
        }
        Label {
            Layout.fillWidth: true
            text: qsTr('Please briefly describe what led to the error (optional):')
        }
        TextArea {
            Layout.fillWidth: true
            Layout.fillHeight: true
            background: Rectangle {
                color: Qt.darker(Material.background, 1.25)
            }
            onTextChanged: AppController.setCrashUserText(text)
        }
        Label {
            text: qsTr('Do you want to send this report?')
        }
        RowLayout {
            Button {
                Layout.fillWidth: true
                Layout.preferredWidth: 3
                text: qsTr('Send Bug Report')
                onClicked: AppController.sendReport()
            }
            Button {
                Layout.fillWidth: true
                Layout.preferredWidth: 2
                text: qsTr('Never')
                onClicked: {
                    AppController.showNever()
                    close()
                }
            }
            Button {
                Layout.fillWidth: true
                Layout.preferredWidth: 2
                text: qsTr('Not Now')
                onClicked: close()
            }
        }
    }

    BusyIndicator {
        anchors.centerIn: parent
        running: _sending
    }

    Component {
        id: report
        ElDialog {
            property string reportText

            z: 3000

            width: parent.width
            height: parent.height

            header: null

            Flickable {
                anchors.fill: parent
                contentHeight: reportLabel.implicitHeight
                interactive: height < contentHeight

                Label {
                    id: reportLabel
                    text: reportText
                    wrapMode: Text.Wrap
                    width: parent.width
                }
            }
        }
    }

    Connections {
        target: AppController
        function onSendingBugreportSuccess(text) {
            _sending = false
            var dialog = app.messageDialog.createObject(app, {
                text: text,
                richText: true
            })
            dialog.open()
            close()
        }
        function onSendingBugreportFailure(text) {
            _sending = false
            var dialog = app.messageDialog.createObject(app, {
                text: text,
                richText: true
            })
            dialog.open()
        }
        function onSendingBugreport() {
            _sending = true
        }
    }
}
