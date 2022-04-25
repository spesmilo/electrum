import QtQuick 2.6
import QtQuick.Layouts 1.0
import QtQuick.Controls 2.14
import QtQuick.Controls.Material 2.0

import org.electrum 1.0

import "controls"

Dialog {
    id: dialog

    property Invoice invoice
    property string invoice_key

    width: parent.width
    height: parent.height

    title: qsTr('Invoice')

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
            text: qsTr('Type')
        }

        Label {
            text: invoice.invoiceType == Invoice.OnchainInvoice
                    ? qsTr('On-chain invoice')
                    : invoice.invoiceType == Invoice.LightningInvoice
                        ? qsTr('Lightning invoice')
                        : ''
            Layout.fillWidth: true
        }

        Label {
            text: qsTr('Description')
        }

        Label {
            text: invoice.message
            Layout.fillWidth: true
        }

        Label {
            text: qsTr('Amount to send')
        }

        RowLayout {
            Layout.fillWidth: true
            Label {
                font.bold: true
                text: Config.formatSats(invoice.amount, false)
            }

            Label {
                text: Config.baseUnit
                color: Material.accentColor
            }

            Label {
                id: fiatValue
                Layout.fillWidth: true
                text: Daemon.fx.enabled
                        ? '(' + Daemon.fx.fiatValue(invoice.amount, false) + ' ' + Daemon.fx.fiatCurrency + ')'
                        : ''
                font.pixelSize: constants.fontSizeMedium
            }
        }

        Label {
            text: qsTr('Expiration')
            visible: true
        }

        Label {
            id: expiration
            text: invoice.time + invoice.expiration
        }

        RowLayout {
            Layout.columnSpan: 2
            Layout.alignment: Qt.AlignHCenter | Qt.AlignBottom
            Layout.fillHeight: true
            spacing: constants.paddingMedium

            Button {
                text: qsTr('Cancel')
                onClicked: dialog.close()
            }

            Button {
                text: qsTr('Save')
//                 enabled: invoice.invoiceType != Invoice.Invalid
                enabled: invoice.invoiceType == Invoice.OnchainInvoice
                onClicked: {
                    invoice.save_invoice()
                    dialog.close()
                }
            }

            Button {
                text: qsTr('Pay now')
                enabled: invoice.invoiceType != Invoice.Invalid // TODO && has funds
                onClicked: {
                    console.log('pay now')
                }
            }
        }

    }

    Component.onCompleted: {
        if (invoice_key != '') {
            invoice.initFromKey(invoice_key)
        }
    }
}
