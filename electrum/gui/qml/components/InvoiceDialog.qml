import QtQuick 2.6
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

    title: qsTr('Invoice')
    standardButtons: invoice_key != '' ? Dialog.Close : Dialog.Cancel

    modal: true
    parent: Overlay.overlay
    Overlay.modal: Rectangle {
        color: "#aa000000"
    }

    GridLayout {
        id: layout
        width: parent.width
        height: parent.height
        columns: 2

        Rectangle {
            height: 1
            Layout.fillWidth: true
            Layout.columnSpan: 2
            color: Material.accentColor
        }

        Label {
            text: qsTr('Amount to send')
            color: Material.accentColor
            Layout.columnSpan: 2
        }

        TextHighlightPane {
            id: amountContainer

            Layout.columnSpan: 2
            Layout.preferredWidth: parent.width //* 0.75
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
                        font.pixelSize: constants.fontSizeXLarge
                        font.family: FixedFont
                        font.bold: true
                        text: Config.formatSats(invoice.amount, false)
                    }

                    Label {
                        Layout.fillWidth: true
                        text: Config.baseUnit
                        color: Material.accentColor
                        font.pixelSize: constants.fontSizeXLarge
                    }

                    Label {
                        id: fiatValue
                        visible: Daemon.fx.enabled
                        text: Daemon.fx.fiatValue(invoice.amount, false)
                        font.pixelSize: constants.fontSizeMedium
                        color: constants.mutedForeground
                    }

                    Label {
                        visible: Daemon.fx.enabled
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
                        amountContainer.editmode = true
                        amountBtc.focus = true
                    }
                }
                GridLayout {
                    visible: amountContainer.editmode
                    Layout.fillWidth: true
                    columns: 2
                    BtcField {
                        id: amountBtc
                        fiatfield: amountFiat
                    }

                    Label {
                        text: Config.baseUnit
                        color: Material.accentColor
                        Layout.fillWidth: true
                    }

                    FiatField {
                        id: amountFiat
                        btcfield: amountBtc
                        visible: Daemon.fx.enabled
                    }

                    Label {
                        visible: Daemon.fx.enabled
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
                        invoice.amount = Config.unitsToSats(amountBtc.text)
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

        Label {
            text: qsTr('Description')
            visible: invoice.message
            Layout.columnSpan: 2
            color: Material.accentColor
        }

        TextHighlightPane {
            visible: invoice.message

            Layout.columnSpan: 2
            Layout.preferredWidth: parent.width
            Layout.alignment: Qt.AlignHCenter

            padding: 0
            leftPadding: constants.paddingMedium

            Label {
                text: invoice.message
                Layout.fillWidth: true
                font.pixelSize: constants.fontSizeXLarge
                wrapMode: Text.Wrap
                elide: Text.ElideRight
            }
        }

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
            visible: invoice.invoiceType == Invoice.OnchainInvoice
            text: qsTr('Address')
            color: Material.accentColor
        }

        Label {
            visible: invoice.invoiceType == Invoice.OnchainInvoice
            Layout.fillWidth: true
            text: invoice.address
            font.family: FixedFont
            wrapMode: Text.Wrap
        }

        Label {
            visible: invoice.invoiceType == Invoice.LightningInvoice
            text: qsTr('Remote Pubkey')
            color: Material.accentColor
        }

        Label {
            visible: invoice.invoiceType == Invoice.LightningInvoice
            Layout.fillWidth: true
            text: invoice.lnprops.pubkey
            font.family: FixedFont
            wrapMode: Text.Wrap
        }

        Label {
            visible: invoice.invoiceType == Invoice.LightningInvoice
            text: qsTr('Route via (t)')
            color: Material.accentColor
        }

        Label {
            visible: invoice.invoiceType == Invoice.LightningInvoice
            Layout.fillWidth: true
            text: invoice.lnprops.t
            font.family: FixedFont
            wrapMode: Text.Wrap
        }

        Label {
            visible: invoice.invoiceType == Invoice.LightningInvoice
            text: qsTr('Route via (r)')
            color: Material.accentColor
        }

        Label {
            visible: invoice.invoiceType == Invoice.LightningInvoice
            Layout.fillWidth: true
            text: invoice.lnprops.r
            font.family: FixedFont
            wrapMode: Text.Wrap
        }

        Label {
            text: qsTr('Status')
            color: Material.accentColor
        }

        Label {
            text: invoice.status_str
        }

        Rectangle {
            height: 1
            Layout.fillWidth: true
            Layout.columnSpan: 2
            color: Material.accentColor
        }

        Item { Layout.preferredHeight: constants.paddingLarge; Layout.preferredWidth: 1 }

        InfoTextArea {
            Layout.columnSpan: 2
            Layout.alignment: Qt.AlignHCenter
            visible: invoice.userinfo
            text: invoice.userinfo
        }

        RowLayout {
            Layout.columnSpan: 2
            Layout.alignment: Qt.AlignHCenter
            spacing: constants.paddingMedium

            Button {
                text: qsTr('Delete')
                icon.source: '../../icons/delete.png'
                visible: invoice_key != ''
                onClicked: {
                    invoice.wallet.delete_invoice(invoice_key)
                    dialog.close()
                }
            }

            FlatButton {
                text: qsTr('Pay')
                icon.source: '../../icons/confirmed.png'
                enabled: invoice.invoiceType != Invoice.Invalid && invoice.canPay
                onClicked: {
                    if (invoice_key == '') // save invoice if not retrieved from key
                        invoice.save_invoice()
                    dialog.close()
                    doPay() // only signal here
                    // if (invoice.invoiceType == Invoice.OnchainInvoice) {
                    //     doPay() // only signal here
                    // } else if (invoice.invoiceType == Invoice.LightningInvoice) {
                    //     doPay() // only signal here
                    // }
                }
            }
        }

        Item { Layout.fillHeight: true; Layout.preferredWidth: 1 }
    }

    Component.onCompleted: {
        if (invoice_key != '') {
            invoice.initFromKey(invoice_key)
        }
        if (invoice.amount.satsInt == 0)
            amountContainer.editmode = true
    }
}
