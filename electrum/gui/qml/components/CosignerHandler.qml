import QtQuick

import org.electrum

// Scanned QR codes that concern the wallets this device signs for without having them.
Item {
    id: root

    // called by the scan dialogs of the app. Returns true if the data was for us.
    function handleScannedData(data) {
        if (Cosigner.isCosignerQr(data)) {
            confirmSetup(data)
            return true
        }
        if (Cosigner.canCosign(data)) {
            if (Cosigner.canUseAppPassword()) {
                signTransaction(data, '')
            } else {
                // the keys of the wallets we sign for are encrypted
                var dialog = app.passwordDialog.createObject(app, {
                    infotext: qsTr('Enter the password of this device to read the transaction.')
                })
                dialog.passwordEntered.connect(function(password) {
                    if (!Cosigner.verifyPassword(password)) {
                        dialog.clearPassword()
                        dialog.errorMessage = qsTr('Invalid Password')
                        return
                    }
                    dialog.close()
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
                showError(qsTr('This is not a cosigner QR code.'))
        })
        scanner.open()
    }

    function confirmSetup(data) {
        var dialog = app.messageDialog.createObject(app, {
            title: qsTr('Cosigner'),
            text: qsTr('Set up this device as the cosigner of your Electrum desktop wallet?'),
            yesno: true
        })
        dialog.accepted.connect(function() {
            setupCosigner(data)
        })
        dialog.open()
    }

    function setupCosigner(data) {
        if (Cosigner.canUseAppPassword() || Cosigner.hasWallets()) {
            // the password of the app encrypts the cosigner key. If it is not
            // available, Cosigner explains what the user has to do first.
            Cosigner.setupCosigner(data, '')
            return
        }
        // There is no wallet on this device. If it already holds keys, they use the password
        // of the app, and the user types that one: letting them choose another password here
        // would leave this device with two of them. Otherwise, they choose it now.
        var dialog = Cosigner.hasCosigners()
            ? app.passwordDialog.createObject(app, {
                infotext: qsTr('Enter the password of this device to store this key.')
            })
            : app.passwordDialog.createObject(app, {
                confirmPassword: true,
                infotext: [
                    qsTr('Choose a password for Electrum.'),
                    qsTr('It encrypts the cosigner key, and the wallets you create on this device.')
                ].join(' ')
            })
        dialog.passwordEntered.connect(function(password) {
            // if this device already holds keys, the password must be the one they use
            if (!Cosigner.verifyPassword(password)) {
                dialog.clearPassword()
                dialog.errorMessage = qsTr('Invalid Password')
                return
            }
            dialog.close()
            Cosigner.setupCosigner(data, password)
        })
        dialog.open()
    }

    function signTransaction(data, password) {
        var summary = Cosigner.loadPsbt(data, password ? password : '')
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
            title: qsTr('Cosigner'),
            iconSource: Qt.resolvedUrl('../../icons/warning.png'),
            text: message
        })
        dialog.open()
    }

    Connections {
        target: Cosigner
        function onAuthRequired(method, authMessage) {
            app.handleAuthRequired(Cosigner, method, authMessage)
        }
        function onCosignerAdded() {
            var dialog = app.messageDialog.createObject(app, {
                title: qsTr('Cosigner'),
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
                title: qsTr('Cosigner'),
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
}
