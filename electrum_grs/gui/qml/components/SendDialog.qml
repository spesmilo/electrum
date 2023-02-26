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

    parent: Overlay.overlay
    modal: true

    Overlay.modal: Rectangle {
        color: "#aa000000"
    }

    header: Item {}
    padding: 0
    topPadding: 0

    function restart() {
        qrscan.restart()
    }

    function dispatch(data) {
        if (bitcoin.isRawTx(data)) {
            txFound(data)
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
                icon.source: '../../icons/tab_receive.png'
                text: qsTr('Invoices')
                enabled: Daemon.currentWallet.invoiceModel.rowCount() // TODO: only count non-expired
                onClicked: {
                    dialog.close()
                    app.stack.push(Qt.resolvedUrl('Invoices.qml'))
                }
            }

            FlatButton {
                Layout.fillWidth: true
                Layout.preferredWidth: 1
                icon.source: '../../icons/paste.png'
                text: qsTr('Paste from clipboard')
                onClicked: dialog.dispatch(AppController.clipboardToText())
            }
        }

    }

    Bitcoin {
        id: bitcoin
    }
}
