import QtQuick
import QtQuick.Layouts
import QtQuick.Controls
import QtQuick.Controls.Material

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
            }

            RowLayout {
                Layout.fillWidth: true
                Layout.rightMargin: constants.paddingXLarge
                Layout.topMargin: constants.paddingLarge
                Layout.bottomMargin: constants.paddingLarge

                visible: confirmPassword

                Label {
                    text: qsTr('Strength')
                    color: Material.accentColor
                    font.pixelSize: constants.fontSizeSmall
                }

                PasswordStrengthIndicator {
                    Layout.fillWidth: true
                    password: pw_1.text
                }
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
