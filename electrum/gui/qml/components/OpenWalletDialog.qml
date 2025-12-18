import QtQuick
import QtQuick.Layouts
import QtQuick.Controls
import QtQuick.Controls.Material

import org.electrum 1.0

import "controls"

ElDialog {
    id: openwalletdialog

    property string name
    property string path
    property bool isStartup

    property bool _invalidPassword: false
    property bool _unlockClicked: false

    title: qsTr('Open Wallet')
    iconSource: Qt.resolvedUrl('../../icons/wallet.png')

    focus: true

    width: parent.width * 4/5
    anchors.centerIn: parent

    padding: 0
    needsSystemBarPadding: false

    ColumnLayout {
        spacing: 0
        width: parent.width

        ColumnLayout {
            id: rootLayout
            Layout.fillWidth: true
            Layout.leftMargin: constants.paddingXXLarge
            Layout.rightMargin: constants.paddingXXLarge
            spacing: constants.paddingLarge

            InfoTextArea {
                id: notice
                text: Daemon.singlePasswordEnabled || isStartup
                    ? qsTr('Please enter password')
                    : qsTr('Wallet <b>%1</b> requires password to unlock').arg(name)
                iconStyle: InfoTextArea.IconStyle.Warn
                Layout.fillWidth: true
            }

            Label {
                text: qsTr('Password')
                Layout.fillWidth: true
                color: Material.accentColor
            }

            PasswordField {
                id: password
                Layout.fillWidth: true
                Layout.leftMargin: constants.paddingXLarge

                onTextChanged: {
                    unlockButton.enabled = true
                    _unlockClicked = false
                    _invalidPassword = false
                }
                onAccepted: {
                    unlock()
                }
            }

            Label {
                Layout.alignment: Qt.AlignHCenter
                text: _invalidPassword && _unlockClicked ? qsTr("Invalid Password") : ''
                color: constants.colorError
                font.pixelSize: constants.fontSizeLarge
            }
        }

        FlatButton {
            id: unlockButton
            Layout.fillWidth: true
            icon.source: '../../icons/unlock.png'
            text: qsTr("Unlock")
            onClicked: {
                unlock()
            }
        }

    }

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
            password.tf.forceActiveFocus()
        }
        function onWalletLoaded() {
            openwalletdialog.close()
        }
    }

    Component.onCompleted: {
        password.tf.forceActiveFocus()
    }
}
