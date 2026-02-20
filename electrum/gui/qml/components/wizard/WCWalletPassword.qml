import QtQuick
import QtQuick.Layouts
import QtQuick.Controls
import QtQuick.Controls.Material

import "../controls"

// We will only end up here if Daemon.singlePasswordEnabled == False.
// If there are existing wallets, the user must reuse the password of one of them.
// This way they are guided towards password unification.
// NOTE: This also needs to be enforced when changing a wallets password.

WizardComponent {
    id: root
    valid: isInputValid()
    property bool enforceExistingPassword: Config.walletShouldUseSinglePassword && Daemon.availableWallets.rowCount() > 0
    property bool passwordMatchesAnyExisting: false

    function apply() {
        wizard_data['password'] = password1.text
        wizard_data['encrypt'] = password1.text != ''
    }

    function isInputValid() {
        if (password1.text == "") {
            return false
        }
        if (enforceExistingPassword) {
            return passwordMatchesAnyExisting
        }
        return password1.text === password2.text && password1.text.length >= 6
    }

    Timer {
        id: passwordComparisonTimer
        interval: 500
        repeat: false
        onTriggered: {
            root.passwordMatchesAnyExisting = Daemon.numWalletsWithPassword(password1.text) > 0
        }
    }

    ColumnLayout {
        anchors.fill: parent

        Label {
            Layout.fillWidth: true
            Layout.bottomMargin: constants.paddingSmall
            text: !enforceExistingPassword ? qsTr('Enter a password to secure access to your wallet') : qsTr('Enter your existing wallet password')
            wrapMode: Text.Wrap
        }

        PasswordField {
            id: password1
            placeholderText: qsTr('Enter password')
            onTextChanged: {
                if (enforceExistingPassword) {
                    root.passwordMatchesAnyExisting = false
                    passwordComparisonTimer.restart()
                }
            }
        }

        PasswordField {
            id: password2
            showReveal: false
            echoMode: password1.echoMode
            visible: !enforceExistingPassword
            placeholderText: qsTr('Enter password (again)')
        }

        RowLayout {
            Layout.fillWidth: true
            Layout.leftMargin: constants.paddingXLarge
            Layout.rightMargin: constants.paddingXLarge
            Layout.topMargin: constants.paddingXLarge

            visible: password1.text != '' && !enforceExistingPassword

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
            visible: (password1.text != password2.text) && !enforceExistingPassword
            iconStyle: InfoTextArea.IconStyle.Warn
            backgroundColor: constants.darkerDialogBackground
        }
        InfoTextArea {
            Layout.alignment: Qt.AlignCenter
            text: qsTr('Password too short')
            visible: (password1.text == password2.text) && password1.text != '' && !valid && !enforceExistingPassword
            iconStyle: InfoTextArea.IconStyle.Warn
            backgroundColor: constants.darkerDialogBackground
        }
        InfoTextArea {
            Layout.alignment: Qt.AlignCenter
            Layout.fillWidth: true
            visible: password1.text == "" && enforceExistingPassword
            text: [
                    qsTr("Use the password of any existing wallet."),
                    qsTr("Creating new wallets with different passwords is not supported.")
                ].join("\n")
            iconStyle: InfoTextArea.IconStyle.Info
            backgroundColor: constants.darkerDialogBackground
        }
        InfoTextArea {
            Layout.alignment: Qt.AlignCenter
            Layout.fillWidth: true
            visible: password1.text != "" && !valid && enforceExistingPassword
            text: qsTr('Password does not match any existing wallets password.')
            iconStyle: InfoTextArea.IconStyle.Warn
            backgroundColor: constants.darkerDialogBackground
        }

        Item {
            Layout.preferredWidth: 1
            Layout.fillHeight: true
        }

    }
}
