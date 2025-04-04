import QtQuick

import org.electrum

import "../../../gui/qml/components/controls"

Item {
    Connections {
        target: AppController ? AppController.plugin('psbt_nostr') : null
        function onCosignerReceivedPsbt(pubkey, event, tx) {
            var dialog = app.messageDialog.createObject(app, {
                text: [
                    qsTr('A transaction was received from your cosigner.'),
                    qsTr('Do you want to open it now?')
                ].join('\n'),
                yesno: true
            })
            dialog.accepted.connect(function () {
                app.stack.push(Qt.resolvedUrl('../../../gui/qml/components/TxDetails.qml'), {
                    rawtx: tx
                })
                target.acceptPsbt(Daemon.currentWallet, event)
            })
            dialog.open()
        }
    }

    property variant export_tx_button: Component {
        FlatButton {
            id: psbt_nostr_send_button
            property variant dialog
            text: qsTr('Nostr')
            icon.source: Qt.resolvedUrl('../../../gui/icons/network.png')
            visible: Daemon.currentWallet.isMultisig && Daemon.currentWallet.walletType != '2fa'
            onClicked: {
                console.log('about to psbt nostr send')
                psbt_nostr_send_button.enabled = false
                AppController.plugin('psbt_nostr').sendPsbt(Daemon.currentWallet, dialog.text)
            }
            Connections {
                target: AppController ? AppController.plugin('psbt_nostr') : null
                function onSendPsbtFailed(message) {
                    psbt_nostr_send_button.enabled = true
                    var dialog = app.messageDialog.createObject(app, {
                        text: qsTr('Sending PSBT to co-signer failed:\n%1').arg(message)
                    })
                    dialog.open()
                }
            }

        }
    }

}
