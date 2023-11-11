import QtQuick
import QtQuick.Layouts
import QtQuick.Controls
import QtQuick.Controls.Material

import "../controls"

WizardComponent {
    valid: password1.text === password2.text && password1.text.length >= 6

    function apply() {
        wizard_data['password'] = password1.text
        wizard_data['encrypt'] = password1.text != ''
    }

    ColumnLayout {
        anchors.fill: parent

        Label {
            Layout.fillWidth: true
            text: Daemon.singlePasswordEnabled
                ? qsTr('Enter password')
                : qsTr('Enter password for %1').arg(wizard_data['wallet_name'])
            wrapMode: Text.Wrap
        }

        PasswordField {
            id: password1
        }

        Label {
            text: qsTr('Enter password (again)')
        }

        PasswordField {
            id: password2
            showReveal: false
            echoMode: password1.echoMode
        }

        RowLayout {
            Layout.fillWidth: true
            Layout.leftMargin: constants.paddingXLarge
            Layout.rightMargin: constants.paddingXLarge
            Layout.topMargin: constants.paddingXLarge

            visible: password1.text != ''

            Label {
                Layout.rightMargin: constants.paddingLarge
                text: qsTr('Strength')
            }

            PasswordStrengthIndicator {
                Layout.fillWidth: true
                password: password1.text
            }
        }

        Item {
            Layout.preferredWidth: 1
            Layout.fillHeight: true
        }

        InfoTextArea {
            Layout.alignment: Qt.AlignCenter
            text: qsTr('Passwords don\'t match')
            visible: password1.text != password2.text
            iconStyle: InfoTextArea.IconStyle.Warn
        }
    }
}
