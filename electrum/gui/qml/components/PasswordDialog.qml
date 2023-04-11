import QtQuick 2.6
import QtQuick.Layouts 1.0
import QtQuick.Controls 2.3
import QtQuick.Controls.Material 2.0

import org.electrum 1.0

import "controls"

ElDialog {
    id: passworddialog

    title: qsTr("Enter Password")
    iconSource: Qt.resolvedUrl('../../icons/lock.png')

    property bool confirmPassword: false
    property string password
    property string infotext

    anchors.centerIn: parent
    width: parent.width * 4/5
    padding: 0

    ColumnLayout {
        id: rootLayout
        width: parent.width
        spacing: 0

        ColumnLayout {
            id: password_layout
            Layout.leftMargin: constants.paddingXXLarge
            Layout.rightMargin: constants.paddingXXLarge

            InfoTextArea {
                visible: infotext
                text: infotext
                Layout.bottomMargin: constants.paddingMedium
                Layout.fillWidth: true
            }

            Label {
                Layout.fillWidth: true
                text: qsTr('Password')
                color: Material.accentColor
            }

            PasswordField {
                id: pw_1
                Layout.leftMargin: constants.paddingXLarge
            }

            Label {
                Layout.fillWidth: true
                text: qsTr('Password (again)')
                visible: confirmPassword
                color: Material.accentColor
            }

            PasswordField {
                id: pw_2
                Layout.leftMargin: constants.paddingXLarge
                visible: confirmPassword
                showReveal: false
                echoMode: pw_1.echoMode
                enabled: pw_1.text.length >= 6
            }
        }

        FlatButton {
            Layout.fillWidth: true
            text: qsTr("Ok")
            icon.source: '../../icons/confirmed.png'
            enabled: confirmPassword ? pw_1.text.length >= 6 && pw_1.text == pw_2.text : true
            onClicked: {
                password = pw_1.text
                passworddialog.doAccept()
            }
        }
    }
}
