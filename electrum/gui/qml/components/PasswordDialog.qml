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
    property string infotext
    property string errorMessage

    signal passwordEntered(string password)

    anchors.centerIn: parent
    width: parent.width * 4/5
    padding: 0
    needsSystemBarPadding: false

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
                backgroundColor: constants.darkerDialogBackground
                compact: true
            }

            PasswordField {
                id: pw_1
                Layout.bottomMargin: constants.paddingSmall
                placeholderText: qsTr('Password')
            }

            PasswordField {
                id: pw_2
                Layout.bottomMargin: constants.paddingSmall
                visible: confirmPassword
                showReveal: false
                echoMode: pw_1.echoMode
                placeholderText: qsTr('Password (again)')
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
                    Layout.preferredWidth: passworddialog.width / 2
                    password: pw_1.text
                }
            }

            Label {
                Layout.maximumWidth: parent.width
                Layout.alignment: Qt.AlignHCenter
                text: errorMessage
                wrapMode: Text.Wrap
                visible: errorMessage
                color: constants.colorError
                font.pixelSize: constants.fontSizeLarge
            }
        }

        DialogButtonContainer {
            Layout.fillWidth: true

            FlatButton {
                Layout.fillWidth: true
                text: qsTr("Ok")
                icon.source: '../../icons/confirmed.png'
                enabled: confirmPassword ? pw_1.text.length >= 6 && pw_1.text == pw_2.text : true
                onClicked: {
                    passwordEntered(pw_1.text)
                }
            }
        }
    }

    function clearPassword() {
        pw_1.text = ""
        pw_2.text = ""
    }
}
