import QtQuick 2.6
import QtQuick.Controls 2.3
import QtQuick.Layouts 1.0
import QtQuick.Controls.Material 2.0
import QtQml 2.6

import org.electrum 1.0

import "controls"

Item {
    id: mainView

    property string title: Daemon.currentWallet ? Daemon.currentWallet.name : qsTr('no wallet loaded')

    property var _sendDialog
    property string _intentUri

    property string _request_amount
    property string _request_description
    property string _request_expiry

    function openInvoice(key) {
        invoice.key = key
        var dialog = invoiceDialog.createObject(app, { invoice: invoice })
        dialog.open()
        return dialog
    }

    function openRequest(key) {
        var dialog = receiveDialog.createObject(app, { key: key })
        dialog.open()
        return dialog
    }

    function openSendDialog() {
        _sendDialog = sendDialog.createObject(mainView, {invoiceParser: invoiceParser})
        _sendDialog.open()
    }

    function closeSendDialog() {
        if (_sendDialog) {
            _sendDialog.close()
            _sendDialog = null
        }
    }

    function restartSendDialog() {
        if (_sendDialog) {
            _sendDialog.restart()
        }
    }

    function showExportByTxid(txid, helptext) {
        showExport(Daemon.currentWallet.getSerializedTx(txid), helptext)
    }

    function showExport(data, helptext) {
        var dialog = exportTxDialog.createObject(app, {
            text: data[0],
            text_qr: data[1],
            text_help: helptext,
            text_warn: data[2]
                ? ''
                : qsTr('Warning: Some data (prev txs / "full utxos") was left out of the QR code as it would not fit. This might cause issues if signing offline. As a workaround, try exporting the tx as file or text instead.')
        })
        dialog.open()
    }

    property QtObject menu: Menu {
        parent: Overlay.overlay
        dim: true
        modal: true
        Overlay.modal: Rectangle {
            color: "#44000000"
        }

        id: menu

        MenuItem {
            icon.color: action.enabled ? 'transparent' : Material.iconDisabledColor
            icon.source: '../../icons/wallet.png'
            action: Action {
                text: qsTr('Wallet details')
                enabled: Daemon.currentWallet && app.stack.currentItem.objectName != 'WalletDetails'
                onTriggered: menu.openPage(Qt.resolvedUrl('WalletDetails.qml'))
            }
        }
        MenuItem {
            icon.color: action.enabled ? 'transparent' : Material.iconDisabledColor
            icon.source: '../../icons/tab_addresses.png'
            action: Action {
                text: qsTr('Addresses');
                onTriggered: menu.openPage(Qt.resolvedUrl('Addresses.qml'));
                enabled: Daemon.currentWallet && app.stack.currentItem.objectName != 'Addresses'
            }
        }
        MenuItem {
            icon.color: action.enabled ? 'transparent' : Material.iconDisabledColor
            icon.source: '../../icons/lightning.png'
            action: Action {
                text: qsTr('Channels');
                enabled: Daemon.currentWallet && Daemon.currentWallet.isLightning && app.stack.currentItem.objectName != 'Channels'
                onTriggered: menu.openPage(Qt.resolvedUrl('Channels.qml'))
            }
        }

        MenuSeparator { }

        MenuItem {
            icon.color: action.enabled ? 'transparent' : Material.iconDisabledColor
            icon.source: '../../icons/file.png'
            action: Action {
                text: qsTr('Other wallets')
                enabled: app.stack.currentItem.objectName != 'Wallets'
                onTriggered: menu.openPage(Qt.resolvedUrl('Wallets.qml'))
            }
        }

        function openPage(url) {
            stack.pushOnRoot(url)
            currentIndex = -1
        }
    }

    ColumnLayout {
        anchors.fill: parent
        spacing: 0

        History {
            id: history
            visible: Daemon.currentWallet
            Layout.fillWidth: true
            Layout.fillHeight: true
        }

        ColumnLayout {
            Layout.alignment: Qt.AlignHCenter
            Layout.fillHeight: true
            spacing: 2*constants.paddingXLarge
            visible: !Daemon.currentWallet

            Item {
                Layout.fillHeight: true
            }
            Label {
                Layout.alignment: Qt.AlignHCenter
                text: qsTr('No wallet loaded')
                font.pixelSize: constants.fontSizeXXLarge
            }

            Pane {
                Layout.alignment: Qt.AlignHCenter
                padding: 0
                background: Rectangle {
                    color: Material.dialogColor
                }
                FlatButton {
                    text: qsTr('Open/Create Wallet')
                    icon.source: '../../icons/wallet.png'
                    onClicked: {
                        if (Daemon.availableWallets.rowCount() > 0) {
                            stack.push(Qt.resolvedUrl('Wallets.qml'))
                        } else {
                            var newww = app.newWalletWizard.createObject(app)
                            newww.walletCreated.connect(function() {
                                Daemon.availableWallets.reload()
                                // and load the new wallet
                                Daemon.load_wallet(newww.path, newww.wizard_data['password'])
                            })
                            newww.open()
                        }
                    }
                }
            }
            Item {
                Layout.fillHeight: true
            }
        }

        ButtonContainer {
            id: buttonContainer
            Layout.fillWidth: true

            FlatButton {
                id: receiveButton
                visible: Daemon.currentWallet
                Layout.fillWidth: true
                Layout.preferredWidth: 1
                icon.source: '../../icons/tab_receive.png'
                text: qsTr('Receive')
                onClicked: {
                    var dialog = receiveDetailsDialog.createObject(mainView)
                    dialog.open()
                }
                onPressAndHold: {
                    Config.userKnowsPressAndHold = true
                    Daemon.currentWallet.delete_expired_requests()
                    app.stack.push(Qt.resolvedUrl('ReceiveRequests.qml'))
                    AppController.haptic()
                }
            }
            FlatButton {
                visible: Daemon.currentWallet
                Layout.fillWidth: true
                Layout.preferredWidth: 1
                icon.source: '../../icons/tab_send.png'
                text: qsTr('Send')
                onClicked: openSendDialog()
                onPressAndHold: {
                    Config.userKnowsPressAndHold = true
                    app.stack.push(Qt.resolvedUrl('Invoices.qml'))
                    AppController.haptic()
                }
            }
        }
    }

    Invoice {
        id: invoice
        wallet: Daemon.currentWallet
    }

    InvoiceParser {
        id: invoiceParser
        wallet: Daemon.currentWallet
        onValidationError: {
            var dialog = app.messageDialog.createObject(app, { text: message })
            dialog.closed.connect(function() {
                restartSendDialog()
            })
            dialog.open()
        }
        onValidationWarning: {
            if (code == 'no_channels') {
                var dialog = app.messageDialog.createObject(app, { text: message })
                dialog.open()
                // TODO: ask user to open a channel, if funds allow
                // and maybe store invoice if expiry allows
            }
        }
        onValidationSuccess: {
            closeSendDialog()
            var dialog = invoiceDialog.createObject(app, { invoice: invoiceParser, payImmediately: invoiceParser.isLnurlPay })
            dialog.open()
        }
        onInvoiceCreateError: console.log(code + ' ' + message)

        onLnurlRetrieved: {
            closeSendDialog()
            var dialog = lnurlPayDialog.createObject(app, { invoiceParser: invoiceParser })
            dialog.open()
        }
        onLnurlError: {
            var dialog = app.messageDialog.createObject(app, { title: qsTr('Error'), text: message })
            dialog.open()
        }
    }

    Connections {
        target: AppController
        function onUriReceived(uri) {
            console.log('uri received: ' + uri)
            if (!Daemon.currentWallet) {
                console.log('No wallet open, deferring')
                _intentUri = uri
                return
            }
            invoiceParser.recipient = uri
        }
    }

    Connections {
        target: Daemon
        function onWalletLoaded() {
            if (_intentUri) {
                invoiceParser.recipient = _intentUri
                _intentUri = ''
            }
        }
    }

    Connections {
        target: Daemon.currentWallet
        function onRequestCreateSuccess(key) {
            openRequest(key)
        }
        function onRequestCreateError(error) {
            console.log(error)
            var dialog = app.messageDialog.createObject(app, {text: error})
            dialog.open()
        }
        function onOtpRequested() {
            console.log('OTP requested')
            var dialog = otpDialog.createObject(mainView)
            dialog.accepted.connect(function() {
                console.log('accepted ' + dialog.otpauth)
                Daemon.currentWallet.finish_otp(dialog.otpauth)
            })
            dialog.open()
        }
        function onBroadcastFailed(txid, code, message) {
            var dialog = app.messageDialog.createObject(app, {
                text: message
            })
            dialog.open()
        }
    }

    Component {
        id: invoiceDialog
        InvoiceDialog {
            id: _invoiceDialog

            width: parent.width
            height: parent.height

            onDoPay: {
                if (invoice.invoiceType == Invoice.OnchainInvoice
                    || (invoice.invoiceType == Invoice.LightningInvoice
                        && invoice.amountOverride.isEmpty
                            ? invoice.amount.satsInt > Daemon.currentWallet.lightningCanSend
                            : invoice.amountOverride.satsInt > Daemon.currentWallet.lightningCanSend
                        ))
                    {
                    var dialog = confirmPaymentDialog.createObject(mainView, {
                            address: invoice.address,
                            satoshis: invoice.amountOverride.isEmpty ? invoice.amount : invoice.amountOverride,
                            message: invoice.message
                    })
                    var canComplete = !Daemon.currentWallet.isWatchOnly && Daemon.currentWallet.canSignWithoutCosigner
                    dialog.accepted.connect(function() {
                        if (!canComplete) {
                            if (Daemon.currentWallet.isWatchOnly) {
                                dialog.finalizer.save()
                            } else {
                                dialog.finalizer.signAndSave()
                            }
                        } else {
                            dialog.finalizer.signAndSend()
                        }
                    })
                    dialog.open()
                } else if (invoice.invoiceType == Invoice.LightningInvoice) {
                    console.log('About to pay lightning invoice')
                    invoice.pay_lightning_invoice()
                }
            }

            onClosed: destroy()

            Connections {
                target: Daemon.currentWallet
                function onSaveTxSuccess(txid) {
                    _invoiceDialog.close()
                }
            }
        }
    }

    Component {
        id: sendDialog
        SendDialog {
            width: parent.width
            height: parent.height

            onTxFound: {
                app.stack.push(Qt.resolvedUrl('TxDetails.qml'), { rawtx: data })
                close()
            }
            onChannelBackupFound: {
                var dialog = app.messageDialog.createObject(app, {
                    title: qsTr('Import Channel backup?'),
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
        }
    }

    function createRequest(lightning_only, reuse_address) {
        var qamt = Config.unitsToSats(_request_amount)
        Daemon.currentWallet.createRequest(qamt, _request_description, _request_expiry, lightning_only, reuse_address)
    }

    Component {
        id: receiveDetailsDialog

        ReceiveDetailsDialog {
            id: _receiveDetailsDialog
            width: parent.width * 0.9
            anchors.centerIn: parent
            onAccepted: {
                console.log('accepted')
                _request_amount = _receiveDetailsDialog.amount
                _request_description = _receiveDetailsDialog.description
                _request_expiry = _receiveDetailsDialog.expiry
                createRequest(false, false)
            }
            onRejected: {
                console.log('rejected')
            }
            onClosed: destroy()
        }
    }

    Component {
        id: receiveDialog
        ReceiveDialog {
            width: parent.width
            height: parent.height

            onClosed: destroy()
        }
    }

    Component {
        id: confirmPaymentDialog
        ConfirmTxDialog {
            id: _confirmPaymentDialog
            title: qsTr('Confirm Payment')
            finalizer: TxFinalizer {
                wallet: Daemon.currentWallet
                canRbf: true
                onFinishedSave: {
                    if (wallet.isWatchOnly) {
                        // tx was saved. Show QR for signer(s)
                        showExportByTxid(txid, qsTr('Transaction created. Present this QR code to the signing device'))
                    } else {
                        // tx was (partially) signed and saved. Show QR for co-signers or online wallet
                        showExportByTxid(txid, qsTr('Transaction created and partially signed by this wallet. Present this QR code to the next co-signer'))
                    }
                    _confirmPaymentDialog.destroy()
                }
            }
            // TODO: lingering confirmPaymentDialogs can raise exceptions in
            // the child finalizer when currentWallet disappears, but we need
            // it long enough for the finalizer to finish..
            // onClosed: destroy()
        }
    }

    Component {
        id: lightningPaymentProgressDialog
        LightningPaymentProgressDialog {
            onClosed: destroy()
        }
    }

    Component {
        id: lnurlPayDialog
        LnurlPayRequestDialog {
            width: parent.width * 0.9
            anchors.centerIn: parent

            onClosed: destroy()
        }
    }

    Component {
        id: otpDialog
        OtpDialog {
            width: parent.width * 2/3
            anchors.centerIn: parent

            onClosed: destroy()
        }
    }

    Component {
        id: exportTxDialog
        ExportTxDialog {
            onClosed: destroy()
        }
    }

}

