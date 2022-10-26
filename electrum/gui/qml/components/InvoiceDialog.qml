import QtQuick 2.12
import QtQuick.Layouts 1.0
import QtQuick.Controls 2.14
import QtQuick.Controls.Material 2.0

import org.electrum 1.0

import "controls"

ElDialog {
    id: dialog

    property Invoice invoice
    property string invoice_key

    signal doPay
    signal invoiceAmountChanged

    title: qsTr('Invoice')
    standardButtons: invoice_key != '' ? Dialog.Close : Dialog.Cancel

    padding: 0

    modal: true
    parent: Overlay.overlay
    Overlay.modal: Rectangle {
        color: "#aa000000"
    }

    property bool _canMax: invoice.invoiceType == Invoice.OnchainInvoice

    ColumnLayout {
        width: parent.width
        height: parent.height
        spacing: 0

        GridLayout {
            id: layout
            width: parent.width
            Layout.leftMargin: constants.paddingLarge
            Layout.rightMargin: constants.paddingLarge
            columns: 2

            Label {
                text: qsTr('Type')
                color: Material.accentColor
            }

            RowLayout {
                Layout.fillWidth: true
                Image {
                    Layout.preferredWidth: constants.iconSizeSmall
                    Layout.preferredHeight: constants.iconSizeSmall
                    source: invoice.invoiceType == Invoice.LightningInvoice
                        ? "../../icons/lightning.png"
                        : "../../icons/bitcoin.png"
                }

                Label {
                    text: invoice.invoiceType == Invoice.OnchainInvoice
                            ? qsTr('On chain')
                            : invoice.invoiceType == Invoice.LightningInvoice
                                ? qsTr('Lightning')
                                : ''
                    Layout.fillWidth: true
                }
            }

            Label {
                text: qsTr('Status')
                color: Material.accentColor
            }

            Label {
                text: invoice.status_str
            }

            Label {
                visible: invoice.invoiceType == Invoice.OnchainInvoice
                Layout.columnSpan: 2
                text: qsTr('Address')
                color: Material.accentColor
            }

            TextHighlightPane {
                visible: invoice.invoiceType == Invoice.OnchainInvoice

                Layout.columnSpan: 2
                Layout.fillWidth: true

                padding: 0
                leftPadding: constants.paddingMedium

                Label {
                    width: parent.width
                    text: invoice.address
                    font.family: FixedFont
                    wrapMode: Text.Wrap
                }
            }

            Label {
                visible: invoice.invoiceType == Invoice.LightningInvoice
                text: qsTr('Remote Pubkey')
                color: Material.accentColor
            }

            TextHighlightPane {
                visible: invoice.invoiceType == Invoice.LightningInvoice

                Layout.columnSpan: 2
                Layout.fillWidth: true

                padding: 0
                leftPadding: constants.paddingMedium

                Label {
                    width: parent.width
                    text: 'pubkey' in invoice.lnprops ? invoice.lnprops.pubkey : ''
                    font.family: FixedFont
                    wrapMode: Text.Wrap
                }
            }

            Label {
                visible: invoice.invoiceType == Invoice.LightningInvoice
                text: qsTr('Payment hash')
                color: Material.accentColor
            }

            TextHighlightPane {
                visible: invoice.invoiceType == Invoice.LightningInvoice

                Layout.columnSpan: 2
                Layout.fillWidth: true

                padding: 0
                leftPadding: constants.paddingMedium

                Label {
                    width: parent.width
                    text: 'payment_hash' in invoice.lnprops ? invoice.lnprops.payment_hash : ''
                    font.family: FixedFont
                    wrapMode: Text.Wrap
                }
            }

            Label {
                text: qsTr('Description')
                visible: invoice.message
                Layout.columnSpan: 2
                color: Material.accentColor
            }

            TextHighlightPane {
                visible: invoice.message

                Layout.columnSpan: 2
                Layout.fillWidth: true
                Layout.alignment: Qt.AlignHCenter

                padding: 0
                leftPadding: constants.paddingMedium

                Label {
                    text: invoice.message
                    width: parent.width
                    font.pixelSize: constants.fontSizeXLarge
                    wrapMode: Text.Wrap
                    elide: Text.ElideRight
                }
            }

            Label {
                text: qsTr('Amount to send')
                color: Material.accentColor
                Layout.columnSpan: 2
            }

            TextHighlightPane {
                id: amountContainer

                Layout.columnSpan: 2
                Layout.fillWidth: true
                Layout.alignment: Qt.AlignHCenter

                padding: 0
                leftPadding: constants.paddingXXLarge

                property bool editmode: false

                RowLayout {
                    id: amountLayout
                    width: parent.width

                    GridLayout {
                        visible: !amountContainer.editmode
                        columns: 2

                        Label {
                            visible: invoice.amount.isMax
                            Layout.columnSpan: 2
                            font.pixelSize: constants.fontSizeXLarge
                            font.bold: true
                            Layout.fillWidth: true
                            text: qsTr('All on-chain funds')
                        }

                        Label {
                            visible: !invoice.amount.isMax
                            font.pixelSize: constants.fontSizeXLarge
                            font.family: FixedFont
                            font.bold: true
                            text: Config.formatSats(invoice.amount, false)
                        }

                        Label {
                            visible: !invoice.amount.isMax
                            Layout.fillWidth: true
                            text: Config.baseUnit
                            color: Material.accentColor
                            font.pixelSize: constants.fontSizeXLarge
                        }

                        Label {
                            id: fiatValue
                            visible: Daemon.fx.enabled && !invoice.amount.isMax
                            text: Daemon.fx.fiatValue(invoice.amount, false)
                            font.pixelSize: constants.fontSizeMedium
                            color: constants.mutedForeground
                        }

                        Label {
                            visible: Daemon.fx.enabled && !invoice.amount.isMax
                            Layout.fillWidth: true
                            text: Daemon.fx.fiatCurrency
                            font.pixelSize: constants.fontSizeMedium
                            color: constants.mutedForeground
                        }

                    }

                    ToolButton {
                        visible: !amountContainer.editmode
                        icon.source: '../../icons/pen.png'
                        icon.color: 'transparent'
                        onClicked: {
                            amountBtc.text = invoice.amount.satsInt == 0 ? '' : Config.formatSats(invoice.amount)
                            amountMax.checked = invoice.amount.isMax
                            amountContainer.editmode = true
                            amountBtc.focus = true
                        }
                    }
                    GridLayout {
                        visible: amountContainer.editmode
                        Layout.fillWidth: true
                        columns: 3
                        BtcField {
                            id: amountBtc
                            fiatfield: amountFiat
                            enabled: !amountMax.checked
                        }

                        Label {
                            text: Config.baseUnit
                            color: Material.accentColor
                            Layout.fillWidth: amountMax.visible ? false : true
                            Layout.columnSpan: amountMax.visible ? 1 : 2
                        }
                        Switch {
                            id: amountMax
                            text: qsTr('Max')
                            visible: _canMax
                            Layout.fillWidth: true
                            checked: invoice.amount.isMax
                            onCheckedChanged: {
                                if (activeFocus) {
                                    invoice.amount.isMax = checked
                                }
                            }
                        }

                        FiatField {
                            id: amountFiat
                            btcfield: amountBtc
                            visible: Daemon.fx.enabled && !amountMax.checked
                            enabled: !amountMax.checked
                        }

                        Label {
                            Layout.columnSpan: 2
                            visible: Daemon.fx.enabled && !amountMax.checked
                            text: Daemon.fx.fiatCurrency
                            color: Material.accentColor
                        }
                    }
                    ToolButton {
                        visible: amountContainer.editmode
                        Layout.fillWidth: false
                        icon.source: '../../icons/confirmed.png'
                        icon.color: 'transparent'
                        onClicked: {
                            amountContainer.editmode = false
                            invoice.amount = amountMax.checked ? MAX : Config.unitsToSats(amountBtc.text)
                            invoiceAmountChanged()
                        }
                    }
                    ToolButton {
                        visible: amountContainer.editmode
                        Layout.fillWidth: false
                        icon.source: '../../icons/closebutton.png'
                        icon.color: 'transparent'
                        onClicked: amountContainer.editmode = false
                    }
                }

            }

            Item { Layout.preferredHeight: constants.paddingLarge; Layout.preferredWidth: 1 }

            InfoTextArea {
                Layout.columnSpan: 2
                Layout.alignment: Qt.AlignHCenter
                Layout.preferredWidth: parent.width * 3/4
                visible: invoice.userinfo
                text: invoice.userinfo
            }
        }

        Item { Layout.fillHeight: true; Layout.preferredWidth: 1 }

        FlatButton {
            Layout.fillWidth: true
            text: qsTr('Pay')
            icon.source: '../../icons/confirmed.png'
            enabled: invoice.invoiceType != Invoice.Invalid && invoice.canPay && !amountContainer.editmode
            onClicked: {
                if (invoice_key == '') // save invoice if not retrieved from key
                    invoice.save_invoice()
                dialog.close()
                doPay() // only signal here
            }
        }
        FlatButton {
            Layout.fillWidth: true
            text: qsTr('Delete')
            icon.source: '../../icons/delete.png'
            visible: invoice_key != ''
            onClicked: {
                invoice.wallet.delete_invoice(invoice_key)
                dialog.close()
            }
        }

        FlatButton {
            Layout.fillWidth: true
            text: qsTr('Save')
            icon.source: '../../icons/save.png'
            visible: invoice_key == ''
            enabled: invoice.canSave
            onClicked: {
                app.stack.push(Qt.resolvedUrl('Invoices.qml'))
                invoice.save_invoice()
                dialog.close()
            }
        }

    }

    Component.onCompleted: {
        if (invoice_key != '') {
            invoice.initFromKey(invoice_key)
        }
        if (invoice.amount.isEmpty)
            amountContainer.editmode = true
    }
}
