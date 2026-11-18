import QtQuick
import QtQuick.Layouts

import org.electrum

import "../../../gui/qml/components_m3/controls"

// Material 3 QML of the psbt_nostr plugin (multisig: PSBTs to and from co-signers over Nostr). Loaded only by the
// Material 3 GUI (components_m3/main.qml onPluginLoaded: plugins/<name>/qml_m3/ first, M2-MAP F-11); the classic
// GUI keeps loading qml/main.qml.
// repeats: plugins/psbt_nostr/qml/main.qml:7-80 @ e6df7e1c8: on cosignerReceivedPsbt the receive dialog with the
// label and can_be_saved; Open -> saveTxLabel, the transaction details with rawtx and acceptPsbt when that page is
// closed; Save to Wallet -> acceptPsbt(..., true); Discard -> rejectPsbt; the button `export_tx_button` of the
// export dialog (created by ExportTxDialog with { dialog }): shown when canSendPsbt(wallet, dialog.text), a tap
// disables it and calls sendPsbt(wallet, dialog.text, dialog.tx_label); on sendPsbtSuccess the export dialog closes
// and a message tells so, on sendPsbtFailed the button is enabled again and a warning shows the reason.
// Differences: the details are the Material 3 TxDetailsPage, opened by its route (app.pushPage(app.routes.txDetails));
// when no page is shown (the app tells the user when it could not be opened) the PSBT is accepted at once, as after
// closing the page (it is never left pending); the button is an M3Button with the send glyph; the warning passes
// the Material 3 glyph.
// Strings keep the translation context of the classic file (qsTranslate('main', ...)).
Item {
    Connections {
        target: AppController ? AppController.plugin('psbt_nostr') : null
        function onCosignerReceivedPsbt(pubkey, event, tx, label, can_be_saved) {
            var dialog = psbtReceiveDialog.createObject(app, {
                tx_label: label,
                can_be_saved: can_be_saved
            })
            dialog.accepted.connect(function () {
                if (dialog.choice == PsbtReceiveDialog.Choice.Open) {
                    console.log('label:' + label)
                    console.log('tx:' + tx)
                    target.saveTxLabel(Daemon.currentWallet, tx, label)
                    var page = app.pushPage(app.routes.txDetails, {
                        rawtx: tx
                    })
                    if (page) {
                        page.closed.connect(function () {
                            target.acceptPsbt(Daemon.currentWallet, event)
                        })
                    } else {
                        // M3: no page now (when it could not be opened, the app told the user): accept as on close
                        console.log('psbt_nostr: the transaction details are not shown')
                        target.acceptPsbt(Daemon.currentWallet, event)
                    }
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
        M3Button {
            id: psbt_nostr_send_button
            property variant dialog
            variant: 'tonal'
            size: 56
            text: qsTranslate('main', 'Nostr')
            icon.source: Qt.resolvedUrl('../../../gui/icons/m3/send.png')
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
                        text: qsTranslate('main', 'PSBT sent successfully')
                    })
                    msgdialog.open()
                }
                function onSendPsbtFailed(message) {
                    psbt_nostr_send_button.enabled = true
                    var msgdialog = app.messageDialog.createObject(app, {
                        text: qsTranslate('main', 'Sending PSBT to co-signer failed:\n%1').arg(message),
                        iconSource: Qt.resolvedUrl('../../../gui/icons/m3/warning.png')
                    })
                    msgdialog.open()
                }
            }
        }
    }
}
