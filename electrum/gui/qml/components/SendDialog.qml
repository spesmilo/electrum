import QtQuick
import QtQuick.Controls
import QtQuick.Layouts
import QtQuick.Controls.Material

import org.electrum 1.0

import "controls"

// currently not used on android, kept for future use when qt6 camera stops crashing
ElDialog {
    id: dialog

    property InvoiceParser invoiceParser

    signal txFound(data: string)
    signal channelBackupFound(data: string)

    header: null
    padding: 0
    topPadding: 0

    onAboutToHide: {
        console.log('about to hide')
        qrscan.stop()
    }

    function restart() {
        qrscan.restart()
    }

    function dispatch(data) {
        data = data.trim()
        if (bitcoin.isRawTx(data)) {
            txFound(data)
        } else if (Daemon.currentWallet.isValidChannelBackup(data)) {
            channelBackupFound(data)
        } else {
            invoiceParser.recipient = data
        }
    }

    // override
    function doClose() {
        console.log('SendDialog doClose override') // doesn't trigger when going back??
        qrscan.stop()
        Qt.callLater(doReject)
    }

    ColumnLayout {
        anchors.fill: parent
        spacing: 0

        QRScan {
            id: qrscan
            Layout.fillWidth: true
            Layout.fillHeight: true

            hint: Daemon.currentWallet.isLightning
                ? qsTr('Scan an Invoice, an Address, an LNURL-pay, a PSBT or a Channel Backup')
                : qsTr('Scan an Invoice, an Address, an LNURL-pay or a PSBT')
            onFound: dialog.dispatch(scanData)
        }

        ButtonContainer {
            Layout.fillWidth: true

            FlatButton {
                Layout.fillWidth: true
                Layout.preferredWidth: 1
                enabled: !invoiceParser.busy
                icon.source: '../../icons/copy_bw.png'
                text: qsTr('Paste')
                onClicked: {
                    qrscan.stop()
                    dialog.dispatch(AppController.clipboardToText())
                }
            }
        }

    }

    Bitcoin {
        id: bitcoin
    }
}
