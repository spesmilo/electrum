import QtQuick
import QtQuick.Layouts
import QtQuick.Controls
import QtQuick.Controls.Material

import QtQml

import "controls"

ElDialog
{
    id: root

    property var crashData

    property bool _sending: false

    width: parent.width
    height: parent.height
    z: 1000  // assure topmost of all other dialogs. note: child popups need even higher!
    // disable padding in ElDialog as it is overwritten here and shows no effect, this dialog needs padding though
    needsSystemBarPadding: false

    header: null

    ColumnLayout {
        anchors.topMargin: app.statusBarHeight  // edge-to-edge layout padding
        anchors.bottomMargin: app.navigationBarHeight
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
        Flickable {
            width: parent.width
            Layout.fillHeight: true
            contentHeight: user_text.height
            interactive: height < contentHeight
            clip: true

            TextArea {
                id: user_text
                width: parent.width
                height: Math.max(implicitHeight, 100)
                wrapMode: TextInput.WordWrap
                background: Rectangle {
                    color: Qt.darker(Material.background, 1.25)
                }
            }
        }
        Label {
            text: qsTr('Do you want to send this report?')
        }
        RowLayout {
            Button {
                Layout.fillWidth: true
                Layout.preferredWidth: 3
                text: qsTr('Send Bug Report')
                onClicked: {
                    var dialog = app.messageDialog.createObject(app, {
                        text: qsTr('Confirm to send bugreport?'),
                        yesno: true,
                        z: 1001  // assure topmost of all other dialogs
                    })
                    dialog.accepted.connect(function() {
                        AppController.sendReport(user_text.text)
                    })
                    dialog.open()
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

            width: parent.width
            height: parent.height
            z: 1001  // above root
            needsSystemBarPadding: false

            header: null

            Flickable {
                anchors.fill: parent
                anchors.topMargin: app.statusBarHeight
                anchors.bottomMargin: app.navigationBarHeight
                contentHeight: reportLabel.implicitHeight
                interactive: height < contentHeight

                Label {
                    id: reportLabel
                    text: reportText
                    wrapMode: Text.Wrap
                    width: parent.width
                }
            }
            onClosed: destroy()
        }
    }

    Connections {
        target: AppController
        function onSendingBugreportSuccess(text) {
            _sending = false
            var dialog = app.messageDialog.createObject(app, {
                text: text,
                richText: true,
                z: 1001  // assure topmost of all other dialogs
            })
            dialog.open()
            close()
        }
        function onSendingBugreportFailure(text) {
            _sending = false
            var dialog = app.messageDialog.createObject(app, {
                title: qsTr('Error'),
                iconSource: Qt.resolvedUrl('../../icons/warning.png'),
                text: text,
                richText: true,
                z: 1001  // assure topmost of all other dialogs
            })
            dialog.open()
        }
        function onSendingBugreport() {
            _sending = true
        }
    }
}
