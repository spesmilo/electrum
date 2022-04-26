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

    signal doPay

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
            wrapMode: Text.Wrap
            maximumLineCount: 4
            elide: Text.ElideRight
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
            text: qsTr('Status')
        }

        Label {
            text: invoice.status_str
        }

        Item { Layout.fillHeight: true; Layout.preferredWidth: 1 }

        RowLayout {
            Layout.columnSpan: 2
            Layout.alignment: Qt.AlignHCenter
            spacing: constants.paddingMedium

            Button {
                text: qsTr('Cancel')
                onClicked: dialog.close()
            }

            Button {
                text: qsTr('Save')
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
                    invoice.save_invoice()
                    dialog.close()
                    if (invoice.invoiceType == Invoice.OnchainInvoice) {
                        doPay() // only signal here
                    }
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
