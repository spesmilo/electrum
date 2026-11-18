import QtQuick
import QtQuick.Layouts
import QtQuick.Controls
import QtQuick.Controls.Material

import "../controls"

// Material 3 page: password of the new wallet (the last page: "Finish" is enabled only while the page is valid).
// repeats: components/wizard/WCWalletPassword.qml:13-135 (valid by isInputValid(),
// enforceExistingPassword, passwordMatchesAnyExisting, apply(), isInputValid(), the 500 ms comparison timer with
// Daemon.numWalletsWithPassword, the two fields (the second without the reveal button, the echo mode of the first,
// hidden when an existing password is enforced), the strength row, the four messages with their conditions).
// Differences: "Passwords don't match" and "Password too short" are the error text of the second field;
// "Passwords don't match" shows only once the second field is not empty.

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

    function _showFocused() {
        if (password1.field.activeFocus)
            ensureVisible(flick, password1)
        else if (password2.field.activeFocus)
            ensureVisible(flick, password2)
    }

    Flickable {
        id: flick
        anchors.fill: parent
        contentHeight: mainLayout.height + m3.space16
        clip: true
        interactive: height < contentHeight
        boundsBehavior: Flickable.StopAtBounds

        // keep the focused field above the on-screen keyboard (the page shrinks with the keyboard)
        onHeightChanged: root._showFocused()

        ColumnLayout {
            id: mainLayout
            width: parent.width
            spacing: m3.space16

            M3Text {
                Layout.fillWidth: true
                Layout.topMargin: m3.space8
                role: 'titleMedium'
                text: !enforceExistingPassword ? qsTranslate('WCWalletPassword', 'Enter a password to secure access to your wallet') : qsTranslate('WCWalletPassword', 'Enter your existing wallet password')
                wrapMode: Text.Wrap
            }

            M3PasswordField {
                id: password1
                Layout.fillWidth: true
                label: qsTranslate('WCWalletPassword', 'Enter password')
                onTextChanged: {
                    if (enforceExistingPassword) {
                        root.passwordMatchesAnyExisting = false
                        passwordComparisonTimer.restart()
                    }
                }
            }

            M3PasswordField {
                id: password2
                Layout.fillWidth: true
                showReveal: false
                echoMode: password1.echoMode
                visible: !enforceExistingPassword
                label: qsTranslate('WCWalletPassword', 'Enter password (again)')
                errorText: (password1.text != password2.text) && !enforceExistingPassword && password2.text != ''
                    ? qsTranslate('WCWalletPassword', 'Passwords don\'t match')
                    : (password1.text == password2.text) && password1.text != '' && !valid && !enforceExistingPassword
                        ? qsTranslate('WCWalletPassword', 'Password too short')
                        : ''
            }

            RowLayout {
                Layout.fillWidth: true
                spacing: m3.space16

                visible: password1.text != '' && !enforceExistingPassword

                M3Text {
                    Layout.alignment: Qt.AlignTop
                    role: 'labelLarge'
                    color: m3.surfaceVariantOn
                    text: qsTranslate('WCWalletPassword', 'Strength')
                }

                M3PasswordStrength {
                    Layout.fillWidth: true
                    Layout.topMargin: m3.space8
                    password: password1.text
                }
            }

            M3InfoText {
                Layout.fillWidth: true
                visible: password1.text == "" && enforceExistingPassword
                text: [
                        qsTranslate('WCWalletPassword', "Use the password of any existing wallet."),
                        qsTranslate('WCWalletPassword', "Creating new wallets with different passwords is not supported.")
                    ].join("\n")
                tone: 'info'
            }
            M3InfoText {
                Layout.fillWidth: true
                visible: password1.text != "" && !valid && enforceExistingPassword
                text: qsTranslate('WCWalletPassword', 'Password does not match any existing wallets password.')
                tone: 'warn'
            }
        }
    }

    Connections {
        target: password1.field
        function onActiveFocusChanged() { Qt.callLater(root._showFocused) }
    }
    Connections {
        target: password2.field
        function onActiveFocusChanged() { Qt.callLater(root._showFocused) }
    }
}
