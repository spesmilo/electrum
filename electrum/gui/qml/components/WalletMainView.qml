import QtQuick 2.6
import QtQuick.Controls 2.3
import QtQuick.Layouts 1.0
import QtQml 2.6

import org.electrum 1.0

import "controls"

Item {
    id: mainView

    property string title: Daemon.currentWallet ? Daemon.currentWallet.name : ''

    property QtObject menu: Menu {
        id: menu
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

    property var _sendDialog

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
                stack.push(Qt.resolvedUrl('Wallets.qml'))
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
                text: qsTr('Send')
                onClicked: {
                    console.log('send')
                    var comp = Qt.createComponent(Qt.resolvedUrl('SendDialog.qml'))
                    if (comp.status == Component.Error)
                        console.log(comp.errorString())
                    _sendDialog = comp.createObject(mainView, { invoiceParser: invoiceParser } )
                    // dialog.
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
                text: qsTr('Receive')
                onClicked: {
                    var comp = Qt.createComponent(Qt.resolvedUrl('ReceiveDialog.qml'))
                    var dialog = comp.createObject(mainView)
                    dialog.open()
                }
            }
        }
    }

    InvoiceParser {
        id: invoiceParser
        wallet: Daemon.currentWallet
        onValidationError: {
            var dialog = app.messageDialog.createObject(app, {'text': message })
            dialog.open()
        }
        onValidationWarning: {
            if (code == 'no_channels') {
                var dialog = app.messageDialog.createObject(app, {'text': message })
                dialog.open()
                // TODO: ask user to open a channel, if funds allow
                // and maybe store invoice if expiry allows
            }
        }
        onValidationSuccess: {
            _sendDialog.close()
            // address only -> fill form fields and clear this instance
            // else -> show invoice confirmation dialog
            if (invoiceType == Invoice.OnchainOnlyAddress) {
                recipient.text = invoice.recipient
                invoiceParser.clear()
            } else {
                var dialog = invoiceDialog.createObject(app, {'invoice': invoiceParser})
                // dialog.invoice = invoiceParser
                dialog.open()
            }
        }
        onInvoiceCreateError: console.log(code + ' ' + message)

        onInvoiceSaved: {
            Daemon.currentWallet.invoiceModel.init_model()
        }
    }

    Component {
        id: invoiceDialog
    InvoiceDialog {
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
        // onClosed: destroy()
    }
    }

    Component {
        id: confirmPaymentDialog
        ConfirmTxDialog {
            title: qsTr('Confirm Payment')
            finalizer: TxFinalizer {
                wallet: Daemon.currentWallet
                canRbf: true
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

}

