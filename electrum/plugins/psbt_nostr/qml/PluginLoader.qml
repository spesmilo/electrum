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
        function onSendPsbtFailed(reason) {
            console.log('FAIL')
        }
        function onSendPsbtSuccess() {
            console.log('SUCCESS')
        }
    }

    property variant txdetails_button: Component {
        FlatButton {
            property QtObject txdetails
            text: qsTr('to cosigner')
            icon.source: Qt.resolvedUrl('../../../gui/icons/clock3.png')
            visible: !txdetails.isMined && !txdetails.canSign // has signed
            onClicked: {
                console.log('about to psbt nostr send')
                AppController.plugin('psbt_nostr').sendPsbt(Daemon.currentWallet, txdetails.getSerializedTx()[0])
            }
        }
    }
}
