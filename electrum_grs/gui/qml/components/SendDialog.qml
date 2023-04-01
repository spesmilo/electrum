import QtQuick 2.6
import QtQuick.Controls 2.14
import QtQuick.Layouts 1.0
import QtQuick.Controls.Material 2.0

import org.electrum 1.0

import "controls"

ElDialog {
    id: dialog

    property InvoiceParser invoiceParser

    signal txFound(data: string)
    signal channelBackupFound(data: string)

    header: Item {}
    padding: 0
    topPadding: 0

    function restart() {
        qrscan.restart()
    }

    function dispatch(data) {
        if (bitcoin.isRawTx(data)) {
            txFound(data)
        } else if (Daemon.currentWallet.isValidChannelBackup(data)) {
            channelBackupFound(data)
        } else {
            invoiceParser.recipient = data
        }
    }

    ColumnLayout {
        anchors.fill: parent
        spacing: 0

        QRScan {
            id: qrscan
            Layout.preferredWidth: parent.width
            Layout.fillHeight: true

            onFound: dialog.dispatch(scanData)
        }

        ButtonContainer {
            Layout.fillWidth: true

            FlatButton {
                Layout.fillWidth: true
                Layout.preferredWidth: 1
                icon.source: '../../icons/copy_bw.png'
                text: qsTr('Paste')
                onClicked: dialog.dispatch(AppController.clipboardToText())
            }
        }

    }

    Bitcoin {
        id: bitcoin
    }
}
