import QtQuick
import QtQuick.Layouts
import QtQuick.Controls
import QtQuick.Controls.Material

import org.electrum 1.0

import "controls"

ElDialog {
    id: dialog

    title: qsTr('BOLT12 Offer')
    iconSource: '../../../icons/bolt12.png'

    property InvoiceParser invoiceParser

    padding: 0

    property bool commentValid: true // TODO?
    property bool amountValid: amountBtc.textAsSats.satsInt > 0
    property bool valid: commentValid && amountValid

    ColumnLayout {
        width: parent.width

        spacing: 0

        GridLayout {
            id: rootLayout
            columns: 2

            Layout.fillWidth: true
            Layout.leftMargin: constants.paddingLarge
            Layout.rightMargin: constants.paddingLarge
            Layout.bottomMargin: constants.paddingLarge

            // qml quirk; first cells cannot colspan without messing up the grid width
            Item { Layout.fillWidth: true; Layout.preferredWidth: 1; Layout.preferredHeight: 1 }
            Item { Layout.fillWidth: true; Layout.preferredWidth: 1; Layout.preferredHeight: 1 }

            Label {
                Layout.columnSpan: 2
                text: qsTr('Issuer')
                color: Material.accentColor
                visible: 'issuer' in invoiceParser.offerData
            }
            TextHighlightPane {
                Layout.columnSpan: 2
                Layout.fillWidth: true
                visible: 'issuer' in invoiceParser.offerData
                Label {
                    width: parent.width
                    wrapMode: Text.Wrap
                    text: invoiceParser.offerData['issuer']
                }
            }
            Label {
                Layout.columnSpan: 2
                Layout.fillWidth: true
                text: qsTr('Description')
                color: Material.accentColor
            }
            TextHighlightPane {
                Layout.columnSpan: 2
                Layout.fillWidth: true
                Label {
                    width: parent.width
                    text: invoiceParser.offerData['description']
                    wrapMode: Text.Wrap
                }
            }
            Label {
                Layout.columnSpan: 2
                text: qsTr('Amount')
                color: Material.accentColor
            }

            RowLayout {
                Layout.columnSpan: 2
                Layout.fillWidth: true
                BtcField {
                    id: amountBtc
                    Layout.preferredWidth: rootLayout.width /3
                    text: 'amount' in invoiceParser.offerData
                        ? Config.formatSatsForEditing(invoiceParser.offerData['amount']/1000)
                        : ''
                    readOnly: 'amount' in invoiceParser.offerData
                    color: Material.foreground // override gray-out on disabled
                    fiatfield: amountFiat
                    onTextAsSatsChanged: {
                        invoiceParser.amountOverride = textAsSats
                    }
                }
                Label {
                    text: Config.baseUnit
                    color: Material.accentColor
                }
            }

            RowLayout {
                Layout.columnSpan: 2
                visible: Daemon.fx.enabled
                FiatField {
                    id: amountFiat
                    Layout.preferredWidth: rootLayout.width / 3
                    btcfield: amountBtc
                    readOnly: btcfield.readOnly
                }
                Label {
                    text: Daemon.fx.fiatCurrency
                    color: Material.accentColor
                }
            }

            Label {
                Layout.columnSpan: 2
                text: qsTr('Note')
                color: Material.accentColor
            }
            ElTextArea {
                id: note
                Layout.columnSpan: 2
                Layout.fillWidth: true
                Layout.minimumHeight: 100
                wrapMode: TextEdit.Wrap
                placeholderText: qsTr('Enter an (optional) message for the receiver')
                // TODO: max 100 chars is arbitrary, not sure what the max size is
                color: text.length > 100 ? constants.colorError : Material.foreground
            }
        }

        FlatButton {
            Layout.topMargin: constants.paddingLarge
            Layout.fillWidth: true
            text: qsTr('Pay')
            icon.source: '../../icons/confirmed.png'
            enabled: valid
            onClicked: {
                invoiceParser.requestInvoiceFromOffer(note.text)
                dialog.close()
            }
        }
    }

}
