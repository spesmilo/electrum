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
// M3: the adaptation points open the Material 3 SendPage / InvoicePage instead of the classic SendDialog /
// InvoiceDialog: openInvoice, openSendDialog, closeSendDialog, restartSendDialog, onValidationSuccess, plus
// dispatch() (repeats: components/SendDialog.qml:40-85 @ 4f36c4489) and doPay() (the onDoPay handler of the
// classic InvoiceDialog factory, WalletMainView.qml:508-536 @ 4f36c4489, one function for both invoice screens).
// M3: SendPage.qml and InvoicePage.qml are loaded by URL when they are opened, not as types of this file: a defect
// in one of them must not break this file and with it the root of the wallet; when a page cannot be loaded, the
// classic SendDialog / InvoiceDialog is opened instead (logged), so that sending still works.
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

    // M3: fallback, one edit back to the classic InvoiceDialog (the classic factory below is kept for it)
    property bool useClassicInvoiceDialog: false

    property var _sendDialog

    property string _request_amount
    property string _request_description
    property string _request_expiry

    function openInvoice(key) {
        invoice.key = key
        if (useClassicInvoiceDialog) {
            var dialog = invoiceDialog.createObject(app, { invoice: invoice })
            dialog.open()
            return dialog
        }
        // M3: the Material 3 InvoicePage (same contract as InvoiceDialog: invoiceAmountChanged, close())
        var page = _showPage(Qt.resolvedUrl('InvoicePage.qml'), { flow: mainView, invoice: invoice })
        if (page && page.m3InvoicePage === true)
            return page
        console.log('M3: InvoicePage unavailable, opening the classic InvoiceDialog')
        var classicdialog = invoiceDialog.createObject(app, { invoice: invoice })
        classicdialog.open()
        return classicdialog
    }

    function openRequest(key) {
        var dialog = receiveDialog.createObject(app, { key: key })
        dialog.open()
        return dialog
    }

    // M3: loads a Material 3 page of this flow; null (and the error in the log) when it cannot be loaded.
    // The stack is touched only with a ready component: a push or replace of a page that fails to load leaves
    // StackView in a broken state (measured on the stand: after a failed replace, popping the page below kept
    // it on the screen) and returns the current item instead of null.
    function _loadPage(url) {
        var component = Qt.createComponent(url)
        if (component.status !== Component.Ready) {
            console.log('M3: cannot load ' + url + ': ' + component.errorString())
            return null
        }
        return component
    }

    // M3: the Material 3 SendPage on the stack instead of the classic SendDialog
    function openSendDialog() {
        var component = _loadPage(Qt.resolvedUrl('SendPage.qml'))
        var page = component ? app.stack.push(component, { flow: mainView }) : null
        if (page && page.m3SendPage === true) {
            _sendDialog = page
        } else {
            console.log('M3: SendPage unavailable, opening the classic SendDialog')
            _sendDialog = qtSendDialog.createObject(mainView, {invoiceParser: invoiceParser, piResolver: piResolver})
            _sendDialog.open()
        }
    }

    // M3: takes SendPage off the stack, only when it is on top (the page clears _sendDialog itself
    // when it leaves the stack otherwise, e.g. by the back button while a recipient is resolved)
    function closeSendDialog() {
        if (_sendDialog) {
            if (_sendDialog.m3Page !== true)
                _sendDialog.doClose()  // the classic SendDialog (fallback)
            else if (app.stack.currentItem === _sendDialog)
                app.stack.pop()
            else
                console.log('M3: closeSendDialog: SendPage is not on top, left on the stack')
            _sendDialog = null
        }
    }

    function restartSendDialog() {
        if (_sendDialog) {
            _sendDialog.restart()
        }
    }

    // M3: shows a page that follows the recipient input (InvoicePage, TxDetails): it replaces SendPage
    // when SendPage is on top, otherwise it is pushed, so that a scan or a link never takes away the page
    // the user is on. An InvoicePage on top that shows the same invoice object is replaced as well: it would
    // only duplicate the new page (both bound to the one object). While a payment of that page is under way
    // (InvoicePage.paymentUnderway()) it is not replaced, so that its "Payment sent." still comes: the new
    // page is pushed, and the old one is marked superseded (it shows nothing and leaves the stack when the
    // user comes back to it), so that it never offers the new invoice under the old input.
    // Returns the new page, or null when it could not be loaded or the stack did not take it (the stack is
    // then unchanged).
    function _showPage(url, properties) {
        var component = _loadPage(url)
        if (!component)
            return null
        var top = app.stack.currentItem
        var sameInvoice = top && top.m3InvoicePage === true && properties.invoice && top.invoice === properties.invoice
        var replace = top && (top === _sendDialog || (sameInvoice && !top.paymentUnderway()))
        var page = replace
            ? app.stack.replace(top, component, properties)
            : app.stack.push(component, properties)
        if (!page || page === top) {
            console.log('M3: the stack did not take ' + url)
            return null
        }
        if (top === _sendDialog)
            _sendDialog = null
        else if (sameInvoice && !replace)
            top.superseded = true
        return page
    }

    // M3: opens the invoice screen for a validated invoice (onValidationSuccess)
    function _openParsedInvoice() {
        if (useClassicInvoiceDialog) {
            closeSendDialog()
            var dialog = invoiceDialog.createObject(app, {
                invoice: invoiceParser,
                payImmediately: invoiceParser.isLnurlPay
            })
            dialog.open()
            return
        }
        // the classic SendDialog (fallback when SendPage cannot be loaded) is a full screen popup: the page
        // would open under it (WalletMainView.qml:373 @ 4f36c4489 closes it first as well)
        if (_sendDialog && _sendDialog.m3Page !== true)
            closeSendDialog()
        var page = _showPage(Qt.resolvedUrl('InvoicePage.qml'), {
            flow: mainView,
            invoice: invoiceParser,
            payImmediately: invoiceParser.isLnurlPay
        })
        if (!page || page.m3InvoicePage !== true) {
            console.log('M3: InvoicePage unavailable, opening the classic InvoiceDialog')
            closeSendDialog()
            var classicdialog = invoiceDialog.createObject(app, {
                invoice: invoiceParser,
                payImmediately: invoiceParser.isLnurlPay
            })
            classicdialog.open()
        }
    }

    // M3: repeats components/SendDialog.qml:76-85 (dispatch) with its handlers onTxFound (:40-43) and
    // onChannelBackupFound (:45-66) @ 4f36c4489. Called by SendPage and by a scan outside SendPage.
    function dispatch(data) {
        data = data.trim()
        if (bitcoin.isRawTx(data)) {
            _showPage(Qt.resolvedUrl('../components/TxDetails.qml'), { rawtx: data })
        } else if (Daemon.currentWallet.isValidChannelBackup(data)) {
            if (!Daemon.currentWallet.isLightning) {
                var errdialog = app.messageDialog.createObject(app, {
                    title: qsTranslate('SendDialog', 'Cannot import Channel Backup, Lightning not enabled.')
                })
                errdialog.open()
                return
            }
            var dialog = app.messageDialog.createObject(app, {
                title: qsTranslate('SendDialog', 'Import Channel Backup?'),
                yesno: true
            })
            dialog.accepted.connect(function() {
                Daemon.currentWallet.importChannelBackup(data)
                closeSendDialog()
            })
            dialog.rejected.connect(function() {
                closeSendDialog()
            })
            dialog.open()
        } else {
            piResolver.recipient = data
        }
    }

    // M3: the hint of the classic scanner (SendDialog.qml:103-105)
    function scanHint() {
        return Daemon.currentWallet.isLightning
            ? qsTranslate('SendDialog', 'Scan an Invoice, an Address, an LNURL, a PSBT or a Channel Backup')
            : qsTranslate('SendDialog', 'Scan an Invoice, an Address, an LNURL or a PSBT')
    }

    // M3: the classic camera (ScanDialog) for a recipient; the found text goes to onFound (if given, e.g. the
    // field of SendPage) and to dispatch(). For SendPage and for a scan action outside it.
    // onFound may belong to a page that left the stack while the camera was open (a link replaced it):
    // its failure must not lose the scanned text.
    function scanRecipient(onFound) {
        var dialog = app.scanDialog.createObject(app, { hint: scanHint() })
        dialog.onFoundText.connect(function(data) {
            dialog.close()
            if (onFound) {
                try {
                    onFound(data)
                } catch (e) {
                    console.log('M3: scanRecipient: the page of the scan is gone: ' + e)
                }
            }
            dispatch(data)
        })
        dialog.open()
        return dialog
    }

    // M3: the onDoPay handler of the classic InvoiceDialog factory (WalletMainView.qml:508-536 @ 4f36c4489),
    // moved into one function for both invoice screens; `invoicedialog` is the InvoicePage or InvoiceDialog
    // (payOnchain stores the txid in its broadcastTxid).
    function doPay(invoicedialog, invoice) {
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
            payOnchain(invoicedialog, invoice)
        } else if (invoice.invoiceType == Invoice.LightningInvoice) {
            if (lninvoiceButPayOnchain) {
                var dialog = app.messageDialog.createObject(mainView, {
                    title: qsTranslate('WalletMainView', 'Insufficient balance to pay over Lightning. Pay on-chain instead?'),
                    yesno: true
                })
                dialog.accepted.connect(function() {
                    payOnchain(invoicedialog, invoice)
                })
                dialog.open()
            } else {
                console.log('About to pay lightning invoice')
                invoice.payLightningInvoice()
            }
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
            // M3: InvoicePage, or the classic InvoiceDialog when useClassicInvoiceDialog
            _openParsedInvoice()
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

            // M3: one doPay() for both invoice screens
            onDoPay: mainView.doPay(_invoiceDialog, _invoiceDialog.invoice)

            onClosed: destroy()

            Connections {
                target: Daemon.currentWallet
                function onSaveTxSuccess(txid) {
                    _invoiceDialog.close()
                }
            }
        }
    }

    // M3: the classic SendDialog, only as the fallback when SendPage cannot be loaded
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

    // M3: a link that started the app is taken once the root is on the stack: an invoice opens as a page,
    // and StackView refuses a push while it is still completing the push of the root that holds this flow
    function _takeStartupIntent() {
        if (app.pendingIntent) {
            piResolver.recipient = app.pendingIntent
            app.pendingIntent = ""
        }
    }

    Component.onCompleted: {
        console.log("WalletMainView completed: ", Daemon.currentWallet.name)
        Qt.callLater(_takeStartupIntent)
    }
}
