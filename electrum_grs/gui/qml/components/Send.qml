import QtQuick 2.6
import QtQuick.Controls 2.0
import QtQuick.Layouts 1.0
import QtQuick.Controls.Material 2.0
import QtQml.Models 2.1

import org.electrum 1.0

import "controls"

Pane {
    id: rootItem

    function clear() {
        recipient.text = ''
        amount.text = ''
        message.text = ''
        is_max.checked = false
    }

    GridLayout {
        id: form
        width: parent.width
        rowSpacing: constants.paddingSmall
        columnSpacing: constants.paddingSmall
        columns: 3

        BalanceSummary {
            Layout.columnSpan: 3
            Layout.alignment: Qt.AlignHCenter
        }

        Label {
            text: qsTr('Recipient')
        }

        RowLayout {
            Layout.fillWidth: true
            Layout.columnSpan: 2

            TextArea {
                id: recipient
                Layout.fillWidth: true
                font.family: FixedFont
                wrapMode: Text.Wrap
                placeholderText: qsTr('Paste address or invoice')
                onTextChanged: {
                    //if (activeFocus)
                    //userEnteredPayment.recipient = text
                    userEnteredPayment.recipient = recipient.text
                }
            }

            spacing: 0
            ToolButton {
                icon.source: '../../icons/paste.png'
                icon.height: constants.iconSizeMedium
                icon.width: constants.iconSizeMedium
                onClicked: invoice.recipient = AppController.clipboardToText()
            }
            ToolButton {
                icon.source: '../../icons/qrcode.png'
                icon.height: constants.iconSizeMedium
                icon.width: constants.iconSizeMedium
                scale: 1.2
                onClicked: {
                    var page = app.stack.push(Qt.resolvedUrl('Scan.qml'))
                    page.onFound.connect(function() {
                        invoice.recipient = page.scanData
                    })
                }
            }
        }

        Label {
            text: qsTr('Amount')
        }

        BtcField {
            id: amount
            fiatfield: amountFiat
            enabled: !is_max.checked
            Layout.preferredWidth: parent.width /3
            onTextChanged: {
                userEnteredPayment.amount = is_max.checked ? MAX : Config.unitsToSats(amount.text)
            }
        }

        RowLayout {
            Layout.fillWidth: true

            Label {
                text: Config.baseUnit
                color: Material.accentColor
            }
            Switch {
                id: is_max
                text: qsTr('Max')
                onCheckedChanged: {
                    userEnteredPayment.amount = is_max.checked ? MAX : Config.unitsToSats(amount.text)
                }
            }
        }

        Item { width: 1; height: 1; visible: Daemon.fx.enabled }

        FiatField {
            id: amountFiat
            btcfield: amount
            visible: Daemon.fx.enabled
            enabled: !is_max.checked
            Layout.preferredWidth: parent.width /3
        }

        Label {
            Layout.fillWidth: true
            visible: Daemon.fx.enabled
            text: Daemon.fx.fiatCurrency
            color: Material.accentColor
        }

        Label {
            text: qsTr('Description')
        }

        TextField {
            id: message
            placeholderText: qsTr('Message')
            Layout.columnSpan: 2
            Layout.fillWidth: true
            onTextChanged: {
                userEnteredPayment.message = message.text
            }
        }

        RowLayout {
            Layout.columnSpan: 3
            Layout.alignment: Qt.AlignHCenter
            spacing: constants.paddingMedium

            Button {
                text: qsTr('Save')
                enabled: userEnteredPayment.canSave
                icon.source: '../../icons/save.png'
                onClicked: {
                    userEnteredPayment.save_invoice()
                    userEnteredPayment.clear()
                    rootItem.clear()
                }
            }

            Button {
                text: qsTr('Pay now')
                enabled: userEnteredPayment.canPay
                icon.source: '../../icons/confirmed.png'
                onClicked: {
                    var dialog = confirmPaymentDialog.createObject(app, {
                        'address': recipient.text,
                        'satoshis': is_max.checked ? MAX : Config.unitsToSats(amount.text),
                        'message': message.text
                    })
                    dialog.txaccepted.connect(function() {
                        userEnteredPayment.clear()
                        rootItem.clear()
                    })
                    dialog.open()
                }
            }

        }
    }

    Frame {
        verticalPadding: 0
        horizontalPadding: 0

        anchors {
            top: form.bottom
            topMargin: constants.paddingXLarge
            left: parent.left
            right: parent.right
            bottom: parent.bottom
        }

        background: PaneInsetBackground {}

        ColumnLayout {
            spacing: 0
            anchors.fill: parent

            Item {
                Layout.preferredHeight: hitem.height
                Layout.preferredWidth: parent.width
                Rectangle {
                    anchors.fill: parent
                    color: Qt.lighter(Material.background, 1.25)
                }
                RowLayout {
                    id: hitem
                    width: parent.width
                    Label {
                        text: qsTr('Send queue')
                        font.pixelSize: constants.fontSizeLarge
                        color: Material.accentColor
                    }
                }
            }

            ListView {
                id: listview
                Layout.fillHeight: true
                Layout.fillWidth: true
                clip: true

                model: DelegateModel {
                    id: delegateModel
                    model: Daemon.currentWallet.invoiceModel
                    delegate: InvoiceDelegate {
                        onClicked: {
                            var dialog = invoiceDialog.createObject(app, {'invoice' : invoice, 'invoice_key': model.key})
                            dialog.open()
                        }
                    }
                }

                remove: Transition {
                    NumberAnimation { properties: 'scale'; to: 0.75; duration: 300 }
                    NumberAnimation { properties: 'opacity'; to: 0; duration: 300 }
                }
                removeDisplaced: Transition {
                    SequentialAnimation {
                        PauseAnimation { duration: 200 }
                        SpringAnimation { properties: 'y'; duration: 100; spring: 5; damping: 0.5; mass: 2 }
                    }
                }

                ScrollIndicator.vertical: ScrollIndicator { }
            }
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

    Component {
        id: invoiceDialog
        InvoiceDialog {
            onDoPay: {
                if (invoice.invoiceType == Invoice.OnchainInvoice) {
                    var dialog = confirmPaymentDialog.createObject(rootItem, {
                            'address': invoice.address,
                            'satoshis': invoice.amount,
                            'message': invoice.message
                    })
                    dialog.open()
                } else if (invoice.invoiceType == Invoice.LightningInvoice) {
                    console.log('About to pay lightning invoice')
                    if (invoice.key == '') {
                        console.log('No invoice key, aborting')
                        return
                    }
                    var dialog = lightningPaymentProgressDialog.createObject(rootItem, {
                        invoice_key: invoice.key
                    })
                    dialog.open()
                    Daemon.currentWallet.pay_lightning_invoice(invoice.key)
                }
            }
            onClosed: destroy()
        }
    }

    Connections {
        target: Daemon.currentWallet
        function onInvoiceStatusChanged(key, status) {
            Daemon.currentWallet.invoiceModel.updateInvoice(key, status)
        }
    }

    // make clicking the dialog background move the scope away from textedit fields
    // so the keyboard goes away
    MouseArea {
        anchors.fill: parent
        z: -1000
        onClicked: parkFocus.focus = true
        FocusScope { id: parkFocus }
    }


    UserEnteredPayment {
        id: userEnteredPayment
        wallet: Daemon.currentWallet

        //onValidationError: {
            //if (recipient.activeFocus) {
                //// no popups when editing
                //return
            //}
            //var dialog = app.messageDialog.createObject(app, {'text': message })
            //dialog.open()
////             rootItem.clear()
        //}

        onInvoiceSaved: {
            Daemon.currentWallet.invoiceModel.init_model()
        }
    }

    InvoiceParser {
        id: invoice
        wallet: Daemon.currentWallet
        onValidationError: {
            if (recipient.activeFocus) {
                // no popups when editing
                return
            }
            var dialog = app.messageDialog.createObject(app, {'text': message })
            dialog.open()
            rootItem.clear()
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
            // address only -> fill form fields and clear this instance
            // else -> show invoice confirmation dialog
            if (invoiceType == Invoice.OnchainOnlyAddress) {
                recipient.text = invoice.recipient
                invoice.clear()
            } else {
                var dialog = invoiceDialog.createObject(rootItem, {'invoice': invoice})
                dialog.open()
            }
        }
        onInvoiceCreateError: console.log(code + ' ' + message)

        onInvoiceSaved: {
            Daemon.currentWallet.invoiceModel.init_model()
        }
    }

}
