import QtQuick
import QtQuick.Layouts
import QtQuick.Controls
import QtQuick.Controls.Material

import org.electrum 1.0

import "controls"

// "Open Wallet" of the Material 3 GUI: the password of a wallet that requires one (app.openWalletDialog, created by
// main.qml showOpenWalletDialog with name, path, isStartup).
// repeats: components/OpenWalletDialog.qml:10-143 (the properties name, path, isStartup,
// _invalidPassword, _unlockClicked; the two texts of the notice; the password field: a change of the text enables
// Unlock and clears the error, Enter unlocks; "Invalid Password" after a failed unlock; unlock() disables Unlock and
// loads the wallet with the password; maybeUnlockAnyOtherWallet() and the conditions of the fallback; on
// Daemon.walletRequiresPassword: the fallback, else the error and the focus back in the field; on Daemon.walletLoaded:
// close; the focus in the field at start).
// Look: an M3Dialog without icon; the notice as text (the classic info box), the
// password as M3PasswordField with "Invalid Password" as its error text, text buttons "Cancel" (doReject(): the same
// as the Android back button and the tap outside, closePolicy of the base) and
// "Unlock". It lives in app.keyboardFreeZone (the base), so it stays above the keyboard.
// Strings carried over keep the translation context of OpenWalletDialog.qml.
M3Dialog {
    id: openwalletdialog

    property string name
    property string path
    property bool isStartup

    property bool _invalidPassword: false
    property bool _unlockClicked: false

    title: qsTranslate('OpenWalletDialog', 'Open Wallet')

    focus: true

    contentItem: ColumnLayout {
        id: rootLayout
        spacing: m3.space16

        M3Text {
            id: notice
            Layout.fillWidth: true
            role: 'bodyMedium'
            color: m3.surfaceVariantOn
            wrapMode: Text.Wrap
            text: Daemon.singlePasswordEnabled || isStartup
                ? qsTranslate('OpenWalletDialog', 'Please enter password')
                : qsTranslate('OpenWalletDialog', 'Wallet <b>%1</b> requires password to unlock').arg(name)
            textFormat: Text.RichText
        }

        M3PasswordField {
            id: password
            Layout.fillWidth: true
            label: qsTranslate('OpenWalletDialog', 'Password')
            errorText: _invalidPassword && _unlockClicked ? qsTranslate('OpenWalletDialog', 'Invalid Password') : ''

            onTextChanged: {
                unlockButton.enabled = true
                _unlockClicked = false
                _invalidPassword = false
            }
            onAccepted: {
                unlock()
            }
        }
    }

    buttons: [
        M3Button {
            id: unlockButton
            variant: 'text'
            text: qsTranslate('OpenWalletDialog', 'Unlock')
            onClicked: {
                unlock()
            }
        },
        M3Button {
            variant: 'text'
            text: qsTranslate('Wizard', 'Cancel')
            onClicked: openwalletdialog.doReject()
        }
    ]

    function unlock() {
        unlockButton.enabled = false
        _unlockClicked = true
        Daemon.loadWallet(openwalletdialog.path, password.text)
    }

    function maybeUnlockAnyOtherWallet() {
        // try to open any other wallet with the password the user entered, hack to improve ux for
        // users with non-unified wallet password.
        // we should only fall back to opening a random wallet if:
        // - the user did not select a specific wallet, otherwise this is confusing
        // - there can be more than one password, otherwise this scan would be pointless
        if (Daemon.availableWallets.rowCount() <= 1 || password.text === '') {
            return false
        }
        if (Config.walletDidUseSinglePassword) {
            // the last time the wallet was unlocked all wallets used the same password.
            // trying to decrypt all of them now is most probably useless.
            return false
        }
        if (!openwalletdialog.isStartup) {
            return false  // this dialog got opened because the user clicked on a specific wallet
        }
        let wallet_paths = Daemon.getWalletsUnlockableWithPassword(password.text)
        if (wallet_paths && wallet_paths.length > 0) {
            console.log('could not unlock recent wallet, falling back to: ' + wallet_paths[0])
            Daemon.loadWallet(wallet_paths[0], password.text)
            return true
        }
        return false
    }

    Connections {
        target: Daemon
        function onWalletRequiresPassword() {
            if (maybeUnlockAnyOtherWallet()) {
                password.text = ''  // reset pw so we cannot end up in a loop
                return
            }
            console.log('invalid password')
            _invalidPassword = true
            password.field.forceActiveFocus()
        }
        function onWalletLoaded() {
            openwalletdialog.close()
        }
    }

    Component.onCompleted: {
        password.field.forceActiveFocus()
    }
}
