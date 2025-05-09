import QtQuick

import org.electrum

import "../../../gui/qml/components/controls"

Item {
    Connections {
        target: AppController ? AppController.plugin('psbt_nostr') : null
        function onCosignerReceivedPsbt(pubkey, event, tx, label) {
            var dialog = psbtReceiveDialog.createObject(app, {
                tx_label: label
            })
            dialog.accepted.connect(function () {
                if (dialog.choice == PsbtReceiveDialog.Choice.Open) {
                    console.log('label:' + label)
                    console.log('tx:' + tx)
                    target.saveTxLabel(Daemon.currentWallet, tx, label)
                    var page = app.stack.push(Qt.resolvedUrl('../../../gui/qml/components/TxDetails.qml'), {
                        rawtx: tx
                    })
                    page.closed.connect(function () {
                        target.acceptPsbt(Daemon.currentWallet, event)
                    })
                } else if (dialog.choice == PsbtReceiveDialog.Choice.Save) {
                    target.acceptPsbt(Daemon.currentWallet, event, true)
                } else {
                    console.log('choice not set')
                }
            })
            dialog.rejected.connect(function () {
                target.rejectPsbt(Daemon.currentWallet, event)
            })
            dialog.open()
        }
    }

    Component {
        id: psbtReceiveDialog
        PsbtReceiveDialog {
            onClosed: destroy()
        }
    }

    property variant export_tx_button: Component {
        FlatButton {
            id: psbt_nostr_send_button
            property variant dialog
            text: qsTr('Nostr')
            icon.source: Qt.resolvedUrl('../../../gui/icons/network.png')
            visible: AppController.plugin('psbt_nostr').canSendPsbt(Daemon.currentWallet, dialog.text)
            onClicked: {
                console.log('about to psbt nostr send')
                psbt_nostr_send_button.enabled = false
                AppController.plugin('psbt_nostr').sendPsbt(Daemon.currentWallet, dialog.text, dialog.tx_label)
            }
            Connections {
                target: AppController ? AppController.plugin('psbt_nostr') : null
                function onSendPsbtSuccess() {
                    dialog.close()
                    var msgdialog = app.messageDialog.createObject(app, {
                        text: qsTr('PSBT sent successfully')
                    })
                    msgdialog.open()
                }
                function onSendPsbtFailed(message) {
                    psbt_nostr_send_button.enabled = true
                    var msgdialog = app.messageDialog.createObject(app, {
                        text: qsTr('Sending PSBT to co-signer failed:\n%1').arg(message),
                        iconSource: Qt.resolvedUrl('../../../gui/icons/warning.png')
                    })
                    msgdialog.open()
                }
            }

        }
    }

}
