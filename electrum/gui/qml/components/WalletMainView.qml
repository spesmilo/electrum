import QtQuick 2.6
import QtQuick.Controls 2.3
import QtQuick.Layouts 1.0
import QtQml 2.6

import org.electrum 1.0

import "controls"

Item {
    id: mainView

    property string title: Daemon.currentWallet ? Daemon.currentWallet.name : ''

    function openInvoice(key) {
        var dialog = invoiceDialog.createObject(app, { invoice: invoiceParser, invoice_key: key })
        dialog.open()
        return dialog
    }

    property QtObject menu: Menu {
        id: menu
        MenuItem {
            icon.color: 'transparent'
            action: Action {
                text: qsTr('Invoices');
                onTriggered: menu.openPage(Qt.resolvedUrl('Invoices.qml'))
                icon.source: '../../icons/tab_receive.png'
            }
        }
        MenuItem {
            icon.color: 'transparent'
            action: Action {
                text: qsTr('Addresses');
                onTriggered: menu.openPage(Qt.resolvedUrl('Addresses.qml'));
                enabled: Daemon.currentWallet
                icon.source: '../../icons/tab_addresses.png'
            }
        }
        MenuItem {
            icon.color: 'transparent'
            action: Action {
                text: qsTr('Wallets');
                onTriggered: menu.openPage(Qt.resolvedUrl('Wallets.qml'))
                icon.source: '../../icons/wallet.png'
            }
        }
        MenuItem {
            icon.color: 'transparent'
            action: Action {
                text: qsTr('Network');
                onTriggered: menu.openPage(Qt.resolvedUrl('NetworkStats.qml'))
                icon.source: '../../icons/network.png'
            }
        }
        MenuItem {
            icon.color: 'transparent'
            action: Action {
                text: qsTr('Channels');
                enabled: Daemon.currentWallet && Daemon.currentWallet.isLightning
                onTriggered: menu.openPage(Qt.resolvedUrl('Channels.qml'))
                icon.source: '../../icons/lightning.png'
            }
        }

        MenuItem {
            icon.color: 'transparent'
            action: Action {
                text: qsTr('Preferences');
                onTriggered: menu.openPage(Qt.resolvedUrl('Preferences.qml'))
                icon.source: '../../icons/preferences.png'
            }
        }

        MenuItem {
            icon.color: 'transparent'
            action: Action {
                text: qsTr('About');
                onTriggered: menu.openPage(Qt.resolvedUrl('About.qml'))
                icon.source: '../../icons/electrum.png'
            }
        }

        function openPage(url) {
            stack.push(url)
            currentIndex = -1
        }
    }

    ColumnLayout {
        anchors.centerIn: parent
        width: parent.width
        spacing: 2*constants.paddingXLarge
        visible: !Daemon.currentWallet

        Label {
            text: qsTr('No wallet loaded')
            font.pixelSize: constants.fontSizeXXLarge
            Layout.alignment: Qt.AlignHCenter
        }

        Button {
            text: qsTr('Open/Create Wallet')
            Layout.alignment: Qt.AlignHCenter
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

    ColumnLayout {
        anchors.fill: parent
        visible: Daemon.currentWallet

        History {
            id: history
            Layout.preferredWidth: parent.width
            Layout.fillHeight: true
        }

        RowLayout {
            spacing: 0

            FlatButton {
                Layout.fillWidth: true
                Layout.preferredWidth: 1
                icon.source: '../../icons/tab_send.png'
                text: qsTr('Send')
                onClicked: {
                    console.log('send')
                    _sendDialog = sendDialog.createObject(mainView, {invoiceParser: invoiceParser})
                    _sendDialog.open()
                }
            }
            Rectangle {
                Layout.fillWidth: false
                Layout.preferredWidth: 2
                Layout.preferredHeight: parent.height * 2/3
                Layout.alignment: Qt.AlignVCenter
                color: constants.darkerBackground
            }
            FlatButton {
                Layout.fillWidth: true
                Layout.preferredWidth: 1
                icon.source: '../../icons/tab_receive.png'
                text: qsTr('Receive')
                onClicked: {
                    var dialog = receiveDialog.createObject(mainView)
                    dialog.open()
                }
            }
        }
    }

    InvoiceParser {
        id: invoiceParser
        wallet: Daemon.currentWallet
        onValidationError: {
            var dialog = app.messageDialog.createObject(app, { text: message })
            dialog.closed.connect(function() {
                _sendDialog.restart()
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
            _sendDialog.close()
            var dialog = invoiceDialog.createObject(app, { invoice: invoiceParser })
            dialog.open()
        }
        onInvoiceCreateError: console.log(code + ' ' + message)

        onLnurlRetrieved: {
            var dialog = lnurlPayDialog.createObject(app, { invoiceParser: invoiceParser })
            dialog.open()
        }

        onInvoiceSaved: {
            Daemon.currentWallet.invoiceModel.init_model()
        }
    }

    Component {
        id: invoiceDialog
        InvoiceDialog {
            width: parent.width
            height: parent.height

            onDoPay: {
                if (invoice.invoiceType == Invoice.OnchainInvoice) {
                    var dialog = confirmPaymentDialog.createObject(mainView, {
                            'address': invoice.address,
                            'satoshis': invoice.amount,
                            'message': invoice.message
                    })
                    var wo = Daemon.currentWallet.isWatchOnly
                    dialog.txaccepted.connect(function() {
                        if (wo) {
                            showUnsignedTx(dialog.finalizer.serializedTx(false), dialog.finalizer.serializedTx(true))
                        } else {
                            dialog.finalizer.send_onchain()
                        }
                    })
                    dialog.open()
                } else if (invoice.invoiceType == Invoice.LightningInvoice) {
                    console.log('About to pay lightning invoice')
                    if (invoice.key == '') {
                        console.log('No invoice key, aborting')
                        return
                    }
                    var dialog = lightningPaymentProgressDialog.createObject(mainView, {
                        invoice_key: invoice.key
                    })
                    dialog.open()
                    Daemon.currentWallet.pay_lightning_invoice(invoice.key)
                }
                close()
            }
            onClosed: destroy()
        }
    }

    property var _sendDialog

    Component {
        id: sendDialog
        SendDialog {
            width: parent.width
            height: parent.height

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
            title: qsTr('Confirm Payment')
            finalizer: TxFinalizer {
                wallet: Daemon.currentWallet
                canRbf: Config.useRbf
            }
            onClosed: destroy()
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
}

