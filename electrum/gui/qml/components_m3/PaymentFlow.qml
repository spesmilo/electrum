import QtQuick
import QtQuick.Controls
import QtQuick.Layouts
import QtQuick.Controls.Material
import QtQml

import org.electrum 1.0

import "../components" as Classic

// Payment flow of the Material 3 GUI: the non-visual part of the classic WalletMainView,
// carried over verbatim from components/WalletMainView.qml @ 4f36c4489, lines 17-134 and 295-705
// (the wallet menu, history list and Send/Receive buttons, lines 136-293, are not carried over).
// It holds the payment identifier resolver, the invoice parser and the dialog factories, which the
// classic dialogs reach by id; the root id `mainView` is required (InvoiceDialog.qml refers to it).
// Differences from the original are marked with `// M3:`; classic types carry the `Classic.` prefix.
// M3: the strings keep the translation context of the classic file, qsTranslate('WalletMainView', ...)
// instead of qsTr (which takes the context from the file name).
Item {
    id: mainView

    // M3: read by the Material 3 pages (busy state, input)
    property alias piResolver: piResolver
    property alias invoiceParser: invoiceParser
    property alias requestDetails: requestDetails

    // M3: the Receive button of the classic WalletMainView (line 265-268) as a function
    function openReceiveDetailsDialog() {
        var dialog = receiveDetailsDialog.createObject(mainView)
        dialog.open()
    }

    property var _sendDialog

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
        _sendDialog = qtSendDialog.createObject(mainView, {invoiceParser: invoiceParser, piResolver: piResolver})
        _sendDialog.open()
    }

    function closeSendDialog() {
        if (_sendDialog) {
            _sendDialog.doClose()
            _sendDialog = null
        }
    }

    function restartSendDialog() {
        if (_sendDialog) {
            _sendDialog.restart()
        }
    }

    function showExport(data, helptext) {
        var dialog = exportTxDialog.createObject(app, {
            text: data[0],
            text_qr: data[1],
            text_help: helptext,
            text_warn: data[2]
                ? ''
                : [qsTranslate('WalletMainView', 'Warning: Some data (prev txs / "full utxos") was left out of the QR code as it would not fit.'),
                   qsTranslate('WalletMainView', 'This might cause issues if signing offline.'),
                   qsTranslate('WalletMainView', 'As a workaround, copy to clipboard or use the Share option instead.')].join(' '),
            tx_label: data[3]
        })
        dialog.open()
    }

    function payOnchain(invoicedialog, invoice) {
        var dialog = confirmPaymentDialog.createObject(mainView, {
                address: invoice.address,
                satoshis: invoice.amountOverride.isEmpty
                    ? invoice.amount
                    : invoice.amountOverride,
                message: invoice.message
        })
        var canComplete = !Daemon.currentWallet.isWatchOnly && Daemon.currentWallet.canSignWithoutCosigner
        dialog.accepted.connect(function() {
            if (invoice.canSave)
                if (!invoice.saveInvoice())
                    return
            if (!canComplete) {
                if (Daemon.currentWallet.isWatchOnly) {
                    dialog.finalizer.saveOrShow()
                } else {
                    dialog.finalizer.sign()
                }
            } else {
                // store txid in invoicedialog so the dialog can detect broadcast success
                invoicedialog.broadcastTxid = dialog.finalizer.finalizedTxid
                dialog.finalizer.signAndSend()
            }
        })
        dialog.open()
    }

    function createRequest(lightning, reuse_address) {
        var qamt = Config.unitsToSats(_request_amount)
        Daemon.currentWallet.createRequest(qamt, _request_description, _request_expiry, lightning, reuse_address)
    }

    function startSweep() {
        var dialog = sweepDialog.createObject(app)
        dialog.accepted.connect(function() {
            var finalizerDialog = confirmSweepDialog.createObject(mainView, {
                privateKeys: dialog.privateKeys,
                message: qsTranslate('WalletMainView', 'Sweep transaction'),
                showOptions: false,
                amountLabelText: qsTranslate('WalletMainView', 'Total sweep amount'),
                sendButtonText: Daemon.currentWallet.isWatchOnly
                    ? qsTranslate('WalletMainView', 'Sweep...')
                    : qsTranslate('WalletMainView', 'Sweep')
            })
            finalizerDialog.accepted.connect(function() {
                if (Daemon.currentWallet.isWatchOnly) {
                    var confirmdialog = app.messageDialog.createObject(mainView, {
                        title: qsTranslate('WalletMainView', 'Confirm Sweep'),
                        text: qsTranslate('WalletMainView', 'Current wallet is watch-only. You might not be able to spend from these addresses.\n\nAre you sure?'),
                        yesno: true
                    })
                    confirmdialog.accepted.connect(function() {
                        finalizerDialog.finalizer.send()
                        close()
                    })
                    confirmdialog.open()
                    return
                }
                console.log("Sending sweep transaction")
                finalizerDialog.finalizer.send()
            })
            finalizerDialog.open()
        })
        dialog.open()
    }

    PIResolver {
        id: piResolver
        wallet: Daemon.currentWallet

        onResolveError: (code, message) => {
            var dialog = app.messageDialog.createObject(app, {
                title: qsTranslate('WalletMainView', 'Error'),
                iconSource: Qt.resolvedUrl('../../icons/warning.png'),
                text: message
            })
            dialog.closed.connect(function() {
                restartSendDialog()
            })
            dialog.open()
        }

        onInvoiceResolved: (pi) => {
            invoiceParser.fromResolvedPaymentIdentifier(pi)
        }

        onRequestResolved: (pi) => {
            requestDetails.fromResolvedPaymentIdentifier(pi)
        }
    }

    RequestDetails {
        id: requestDetails
        wallet: Daemon.currentWallet
        onNeedsLNURLUserInput: {
            closeSendDialog()
            var dialog = lnurlWithdrawDialog.createObject(app, {
                requestDetails: requestDetails
            })
            dialog.open()
        }
        onLnurlError: (code, message) => {
            var dialog = app.messageDialog.createObject(app, {
                title: qsTranslate('WalletMainView', 'Error'),
                iconSource: Qt.resolvedUrl('../../icons/warning.png'),
                text: message
            })
            dialog.open()
        }
    }

    Invoice {
        id: invoice
        wallet: Daemon.currentWallet
    }

    InvoiceParser {
        id: invoiceParser
        wallet: Daemon.currentWallet
        onValidationError: (code, message) => {
            var dialog = app.messageDialog.createObject(app, {
                title: qsTranslate('WalletMainView', 'Error'),
                iconSource: Qt.resolvedUrl('../../icons/warning.png'),
                text: message
            })
            dialog.closed.connect(function() {
                restartSendDialog()
            })
            dialog.open()
        }
        onValidationWarning: (code, message) => {
            if (code == 'no_channels') {
                var dialog = app.messageDialog.createObject(app, {
                    text: message
                })
                dialog.closed.connect(function() {
                    restartSendDialog()
                })
                dialog.open()
                // TODO: ask user to open a channel, if funds allow
                // and maybe store invoice if expiry allows
            }
        }
        onValidationSuccess: {
            closeSendDialog()
            var dialog = invoiceDialog.createObject(app, {
                invoice: invoiceParser,
                payImmediately: invoiceParser.isLnurlPay
            })
            dialog.open()
        }
        onInvoiceCreateError: (code, message) => {
            var msg = qsTranslate('WalletMainView', 'Cannot save invoice') + ': ' + message
            var dialog = app.messageDialog.createObject(app, {
                text: msg
            })
            dialog.open()
        }
        onLnurlRetrieved: {
            closeSendDialog()
            if (invoiceParser.invoiceType === Invoice.Type.LNURLPayRequest) {
                var dialog = lnurlPayDialog.createObject(app, {
                    invoiceParser: invoiceParser
                })
            } else {
                console.log("Unsupported LNURL type:", invoiceParser.invoiceType)
                return
            }
            dialog.open()
        }
        onLnurlError: (code, message) => {
            var dialog = app.messageDialog.createObject(app, {
                title: qsTranslate('WalletMainView', 'Error'),
                iconSource: Qt.resolvedUrl('../../icons/warning.png'),
                text: message
            })
            dialog.open()
        }
    }

    Bitcoin {
        id: bitcoin
    }

    Connections {
        target: Daemon
        function onWalletLoaded() {
            if (!Daemon.currentWallet) {  // wallet got deleted
                app.stack.replaceRoot('Wallets.qml')
                return
            }
            infobanner.hide() // start hidden when switching wallets
        }
    }

    Connections {
        target: app
        function onPendingIntentChanged() {
            if (app.pendingIntent) {
                piResolver.recipient = app.pendingIntent
                app.pendingIntent = ""
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
            var dialog = app.messageDialog.createObject(app, {
                title: qsTranslate('WalletMainView', 'Error'),
                iconSource: Qt.resolvedUrl('../../icons/warning.png'),
                text: error
            })
            dialog.open()
        }
        function onOtpRequested() {
            console.log('OTP requested')
            var dialog = otpDialog.createObject(mainView)
            dialog.open()
        }
        function onBroadcastFailed(txid, code, message) {
            var dialog = app.messageDialog.createObject(app, {
                title: qsTranslate('WalletMainView', 'Error'),
                iconSource: Qt.resolvedUrl('../../icons/warning.png'),
                text: message
            })
            dialog.open()
        }
        function onPaymentFailed(invoice_id, message) {
            var dialog = app.messageDialog.createObject(app, {
                title: qsTranslate('WalletMainView', 'Error'),
                iconSource: Qt.resolvedUrl('../../icons/warning.png'),
                text: message ? message : qsTranslate('WalletMainView', 'Payment failed')
            })
            dialog.open()
        }
        function onImportChannelBackupFailed(message) {
            var dialog = app.messageDialog.createObject(app, {
                title: qsTranslate('WalletMainView', 'Error'),
                iconSource: Qt.resolvedUrl('../../icons/warning.png'),
                text: message
            })
            dialog.open()
        }
        function onBalanceChanged() {
            // ln low reserve warning
            if (Daemon.currentWallet.isLowReserve) {
                var message = [
                    qsTranslate('WalletMainView', 'You do not have enough on-chain funds to protect your Lightning channels.'),
                    qsTranslate('WalletMainView', 'You should have at least %1 on-chain in order to be able to sweep channel outputs.').arg(Config.formatSats(Config.lnUtxoReserve) + ' ' + Config.baseUnit)
                ].join(' ')
                infobanner.show(message, function() {
                    var dialog = app.messageDialog.createObject(app, {
                        text: message + '\n\n' + qsTranslate('WalletMainView', 'Do you want to perform a swap?'),
                        yesno: true
                    })
                    dialog.accepted.connect(function() {
                        app.startSwap()
                    })
                    dialog.open()
                })
            } else {
                infobanner.hide()
            }
        }
    }

    Component {
        id: invoiceDialog
        Classic.InvoiceDialog {
            id: _invoiceDialog

            width: parent.width
            height: parent.height

            onDoPay: {
                var lninvoiceButPayOnchain = false
                if (invoice.invoiceType == Invoice.LightningInvoice && invoice.address) {
                    // ln invoice with fallback
                    var amountToSend = invoice.amountOverride.isEmpty
                        ? invoice.amount.satsInt
                        : invoice.amountOverride.satsInt
                    if (amountToSend > Daemon.currentWallet.lightningCanSend.satsInt) {
                        lninvoiceButPayOnchain = true
                    }
                }
                if (invoice.invoiceType == Invoice.OnchainInvoice) {
                    payOnchain(_invoiceDialog, invoice)
                } else if (invoice.invoiceType == Invoice.LightningInvoice) {
                    if (lninvoiceButPayOnchain) {
                        var dialog = app.messageDialog.createObject(mainView, {
                            title: qsTranslate('WalletMainView', 'Insufficient balance to pay over Lightning. Pay on-chain instead?'),
                            yesno: true
                        })
                        dialog.accepted.connect(function() {
                            payOnchain(_invoiceDialog, invoice)
                        })
                        dialog.open()
                    } else {
                        console.log('About to pay lightning invoice')
                        invoice.payLightningInvoice()
                    }
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
        id: qtSendDialog
        Classic.SendDialog {}
    }

    Component {
        id: receiveDetailsDialog

        Classic.ReceiveDetailsDialog {
            id: _receiveDetailsDialog
            width: parent.width * 0.9
            anchors.centerIn: parent
            onAccepted: {
                console.log('accepted')
                _request_amount = _receiveDetailsDialog.amount
                _request_description = _receiveDetailsDialog.description
                _request_expiry = _receiveDetailsDialog.expiry
                createRequest(_receiveDetailsDialog.isLightning, false)
            }
            onRejected: {
                console.log('rejected')
            }
            onClosed: destroy()
        }
    }

    Component {
        id: receiveDialog
        Classic.ReceiveDialog {
            width: parent.width
            height: parent.height

            onRequestPaid: {
                close()
                if (isLightning) {
                    // M3: path relative to components_m3/
                    app.stack.push(Qt.resolvedUrl('../components/LightningPaymentDetails.qml'), {'key': key})
                } else {
                    // M3: path relative to components_m3/
                    app.stack.push(Qt.resolvedUrl('../components/TxDetails.qml'), {'txid': getPaidTxid()})
                }
            }
            onClosed: destroy()
        }
    }

    Component {
        id: confirmPaymentDialog
        Classic.ConfirmTxDialog {
            id: _confirmPaymentDialog
            title: qsTranslate('WalletMainView', 'Confirm Payment')
            finalizer: TxFinalizer {
                wallet: Daemon.currentWallet
                canRbf: true
                onFinished: (signed, saved, complete) => {
                    if (!complete) {
                        var msg
                        if (wallet.isWatchOnly) {
                            // tx created in watchonly wallet. Show QR for signer(s)
                            if (wallet.isMultisig) {
                                msg = qsTranslate('WalletMainView', 'Transaction created. Present this QR code to one of the co-cigners or signing devices')
                            } else {
                                msg = qsTranslate('WalletMainView', 'Transaction created. Present this QR code to the signing device')
                            }
                        } else {
                            if (signed) {
                                msg = qsTranslate('WalletMainView', 'Transaction created and partially signed by this wallet. Present this QR code to the next co-signer')
                            } else {
                                msg = qsTranslate('WalletMainView', 'Transaction created but not signed by this wallet yet. Sign the transaction and present this QR code to the next co-signer')
                            }
                        }
                        showExport(getSerializedTx(), msg)
                    }
                    _confirmPaymentDialog.destroy()
                }
                onSignError: (message) => {
                    var dialog = app.messageDialog.createObject(mainView, {
                        title: qsTranslate('WalletMainView', 'Error'),
                        text: [qsTranslate('WalletMainView', 'Could not sign tx'), message].join('\n\n'),
                        iconSource: '../../../icons/warning.png'
                    })
                    dialog.open()
                }
            }

            // TODO: lingering confirmPaymentDialogs can raise exceptions in
            // the child finalizer when currentWallet disappears, but we need
            // it long enough for the finalizer to finish..
            // onClosed: destroy()
        }
    }

    Component {
        id: confirmSweepDialog
        Classic.ConfirmTxDialog {
            id: _confirmSweepDialog

            property string privateKeys
            title: qsTranslate('WalletMainView', 'Confirm Sweep')
            satoshis: MAX
            finalizer: SweepFinalizer {
                wallet: Daemon.currentWallet
                canRbf: true
                privateKeys: _confirmSweepDialog.privateKeys
            }
        }
    }

    Component {
        id: lnurlPayDialog
        Classic.LnurlPayRequestDialog {
            width: parent.width * 0.9
            anchors.centerIn: parent

            onClosed: destroy()
        }
    }

    Component {
        id: lnurlWithdrawDialog
        Classic.LnurlWithdrawRequestDialog {
            width: parent.width * 0.9
            anchors.centerIn: parent

            onClosed: destroy()
        }
    }

    Component {
        id: otpDialog
        Classic.OtpDialog {
            width: parent.width * 2/3
            anchors.centerIn: parent

            onClosed: destroy()
        }
    }

    Component {
        id: exportTxDialog
        Classic.ExportTxDialog {
            onClosed: destroy()
        }
    }

    Component {
        id: sweepDialog
        Classic.SweepDialog {
            onClosed: destroy()
        }
    }

    Component.onCompleted: {
        console.log("WalletMainView completed: ", Daemon.currentWallet.name)
        if (app.pendingIntent) {
            piResolver.recipient = app.pendingIntent
            app.pendingIntent = ""
        }
    }
}
