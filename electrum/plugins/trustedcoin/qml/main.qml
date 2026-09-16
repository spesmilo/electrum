import QtQuick

import org.electrum

import "../../../gui/qml/components/controls"

Item {
    id: root

    property QtObject plugin: AppController.plugin('trustedcoin')

    // called by the scan dialogs of the app. Returns true if the data was for us.
    function handleScannedData(data) {
        if (plugin.isCosignerSetupQr(data)) {
            confirmSetup(data)
            return true
        }
        if (plugin.isCosignerPsbt(data)) {
            if (plugin.canUseAppPassword()) {
                signTransaction(data, '')
            } else {
                // the keys of the wallets we cosign for are encrypted
                var dialog = app.passwordDialog.createObject(app, {
                    infotext: qsTr('Enter the password of this device to read the transaction.')
                })
                dialog.passwordEntered.connect(function(password) {
                    signTransaction(data, password)
                })
                dialog.open()
            }
            return true
        }
        return false
    }

    function scanQrCode() {
        var scanner = app.scanDialog.createObject(app, {
            hint: qsTr('Scan a QR code displayed by Electrum desktop')
        })
        scanner.onFoundText.connect(function(data) {
            scanner.close()
            if (!handleScannedData(data.trim()))
                showError(qsTr('This is not a 2FA QR code.'))
        })
        scanner.open()
    }

    function confirmSetup(data) {
        var dialog = app.messageDialog.createObject(app, {
            title: qsTr('Two-factor authentication'),
            text: qsTr('Set up this device as the cosigner of your Electrum desktop wallet?'),
            yesno: true
        })
        dialog.accepted.connect(function() {
            setupCosigner(data)
        })
        dialog.open()
    }

    function setupCosigner(data) {
        if (plugin.canUseAppPassword() || plugin.hasWallets()) {
            // the password of the app encrypts the cosigner key. If it is not
            // available, the plugin explains what the user has to do first.
            plugin.setupCosigner(data, '')
            return
        }
        // there is no wallet on this device yet: the user chooses the password of the app
        var dialog = app.passwordDialog.createObject(app, {
            confirmPassword: true,
            infotext: [
                qsTr('Choose a password for Electrum.'),
                qsTr('It encrypts the cosigner key, and the wallets you create on this device.')
            ].join(' ')
        })
        dialog.passwordEntered.connect(function(password) {
            plugin.setupCosigner(data, password)
        })
        dialog.open()
    }

    function signTransaction(data, password) {
        var summary = plugin.loadPsbt(data, password ? password : '')
        if (summary['error']) {
            showError(summary['error'])
            return
        }
        var dialog = cosignDialog.createObject(app, {
            summary: summary,
            psbt: data,
            password: password ? password : ''
        })
        dialog.open()
    }

    function showError(message) {
        var dialog = app.messageDialog.createObject(app, {
            title: qsTr('Two-factor authentication'),
            iconSource: Qt.resolvedUrl('../../../gui/icons/warning.png'),
            text: message
        })
        dialog.open()
    }

    Connections {
        target: plugin
        function onCosignerAdded() {
            var dialog = app.messageDialog.createObject(app, {
                title: qsTr('Two-factor authentication'),
                text: qsTr('This device is now a cosigner of your desktop wallet.')
            })
            dialog.open()
        }
        function onSetupFailed(message) {
            showError(message)
        }
        function onSignFailed(message) {
            showError(message)
        }
        function onSignSuccess(txid) {
            var dialog = app.messageDialog.createObject(app, {
                title: qsTr('Two-factor authentication'),
                text: [
                    qsTr('The transaction was signed and broadcast.'),
                    txid
                ].join('\n\n')
            })
            dialog.open()
        }
    }

    Component {
        id: cosignDialog
        CosignDialog {
            onClosed: destroy()
        }
    }

    // shown in the wizard, so that this device can be set up as cosigner without a wallet
    property variant wizard_scan_button: Component {
        FlatButton {
            text: qsTr('Scan QR code')
            icon.source: Qt.resolvedUrl('../../../gui/icons/qrcode.png')
            visible: !root.plugin.hasWallets()
            onClicked: root.scanQrCode()
        }
    }
}
