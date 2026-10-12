import QtQuick
import QtQuick.Controls
import QtQuick.Layouts
import QtQuick.Controls.Material

import org.electrum 1.0

import "controls"

ElDialog {
    id: root

    property var invoiceParser  // type: InvoiceParser
    property var piResolver  // type: PIResolver

    signal txFound(data: string)
    signal channelBackupFound(data: string)

    width: parent.width
    height: parent.height

    header: null
    padding: 0
    topPadding: app.statusBarHeight

    onAboutToHide: {
        console.log('about to hide')
        qrscan.stop()
    }

    onTxFound: (data) => {
        app.stack.push(Qt.resolvedUrl('TxDetails.qml'), { rawtx: data })
        close()
    }

    onChannelBackupFound: (data) => {
        if (!Daemon.currentWallet.isLightning) {
            var dialog = app.messageDialog.createObject(app, {
                title: qsTr('Cannot import Channel Backup, Lightning not enabled.')
            })
            dialog.open()
            return
        }

        var dialog = app.messageDialog.createObject(app, {
            title: qsTr('Import Channel Backup?'),
            yesno: true
        })
        dialog.accepted.connect(function() {
            Daemon.currentWallet.importChannelBackup(data)
            close()
        })
        dialog.rejected.connect(function() {
            close()
        })
        dialog.open()
    }

    onClosed: destroy()

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
            piResolver.recipient = data
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
                ? qsTr('Scan an Invoice, an Address, an LNURL, a PSBT or a Channel Backup')
                : qsTr('Scan an Invoice, an Address, an LNURL or a PSBT')

            onFoundText: (data) => {
                root.dispatch(data)
            }
        }

        DialogButtonContainer {
            Layout.fillWidth: true

            FlatButton {
                Layout.fillWidth: true
                Layout.preferredWidth: 1
                enabled: !invoiceParser.busy && !piResolver.busy
                icon.source: '../../icons/copy_bw.png'
                text: qsTr('Paste')
                onClicked: {
                    qrscan.stop()
                    root.dispatch(AppController.clipboardToText())
                }
            }
        }

    }

    Bitcoin {
        id: bitcoin
    }

    // Keep the camera preview out of screenshots and screen recordings.
    Binding {
        target: AppController
        property: 'secureWindow'
        when: root.visible  // enables stacking multiple secureWindow dialogs
        value: true
    }
}
