import QtQuick 2.6
import QtQuick.Layouts 1.0
import QtQuick.Controls 2.3
import QtQuick.Controls.Material 2.0

import org.electrum 1.0

import "controls"

ElDialog {
    id: passworddialog

    title: qsTr("Enter Password")
    iconSource: '../../../icons/lock.png'

    property bool confirmPassword: false
    property string password
    property string infotext

    parent: Overlay.overlay
    modal: true
    x: (parent.width - width) / 2
    y: (parent.height - height) / 2
    Overlay.modal: Rectangle {
        color: "#aa000000"
    }

    ColumnLayout {
        width: parent.width

        InfoTextArea {
            visible: infotext
            text: infotext
            Layout.preferredWidth: password_layout.width
        }

        GridLayout {
            id: password_layout
            columns: 2
            Layout.fillWidth: true
            Layout.margins: constants.paddingXXLarge

            Label {
                text: qsTr('Password')
            }

            PasswordField {
                id: pw_1
            }

            Label {
                text: qsTr('Password (again)')
                visible: confirmPassword
            }

            PasswordField {
                id: pw_2
                visible: confirmPassword
            }
        }

        RowLayout {
            Layout.alignment: Qt.AlignHCenter
            Layout.topMargin: constants.paddingXXLarge

            Button {
                text: qsTr("Ok")
                enabled: confirmPassword ? pw_1.text == pw_2.text : true
                onClicked: {
                    password = pw_1.text
                    passworddialog.accept()
                }
            }
            Button {
                text: qsTr("Cancel")
                onClicked: {
                    passworddialog.reject()
                }
            }
        }
    }

}
