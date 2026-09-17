import QtQuick
import QtQuick.Layouts
import QtQuick.Controls
import QtQuick.Controls.Material

import org.electrum 1.0

import "controls"

ElDialog {
    id: dialog

    title: qsTr('Lightning Offer')
    iconSource: '../../../icons/lightning.png'

    property var invoiceParser  // type: InvoiceParser

    padding: 0

    property bool commentValid: note.text.length <= 64
    property bool amountValid: amountBtc.textAsSats.satsInt > 0 && amountBtc.textAsSats.satsInt <= Daemon.currentWallet.lightningCanSend.satsInt
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
                Layout.topMargin: constants.paddingSmall
                text: qsTr('Issuer')
                color: Material.accentColor
                visible: 'issuer' in invoiceParser.offerData
            }
            TextHighlightPane {
                Layout.columnSpan: 2
                Layout.fillWidth: true
                visible: 'issuer' in invoiceParser.offerData
                leftPadding: constants.paddingMedium
                Label {
                    width: parent.width
                    wrapMode: Text.Wrap
                    elide: Text.ElideRight
                    font.pixelSize: constants.fontSizeXLarge
                    text: 'issuer' in invoiceParser.offerData ? invoiceParser.offerData['issuer'] : ''
                }
            }
            Label {
                Layout.columnSpan: 2
                Layout.fillWidth: true
                Layout.topMargin: constants.paddingSmall
                text: qsTr('Description')
                color: Material.accentColor
                visible: 'description' in invoiceParser.offerData
            }
            TextHighlightPane {
                Layout.columnSpan: 2
                Layout.fillWidth: true
                visible: 'description' in invoiceParser.offerData
                leftPadding: constants.paddingMedium
                Label {
                    width: parent.width
                    text: 'description' in invoiceParser.offerData ? invoiceParser.offerData['description'] : ''
                    wrapMode: Text.Wrap
                    font.pixelSize: constants.fontSizeXLarge
                }
            }
            Label {
                Layout.columnSpan: 2
                Layout.topMargin: constants.paddingSmall
                text: qsTr('Amount')
                color: Material.accentColor
            }

            DialogHighlightPane {
                Layout.columnSpan: 2
                Layout.fillWidth: true

                ColumnLayout {
                    width: parent.width
                    spacing: constants.paddingSmall

                    RowLayout {
                        Layout.fillWidth: true
                        BtcField {
                            id: amountBtc
                            Layout.preferredWidth: rootLayout.width / 3
                            text: 'amount_msat' in invoiceParser.offerData
                                ? Config.formatSatsForEditing(invoiceParser.offerData['amount_msat'] / 1000)
                                : ''
                            readOnly: 'amount_msat' in invoiceParser.offerData
                            // accent color for fixed-amount offers; also overrides gray-out on disabled
                            color: readOnly ? Material.accentColor : Material.foreground
                            fiatfield: amountFiat
                            onTextAsSatsChanged: {
                                if (textAsSats)
                                    invoiceParser.amountOverride = textAsSats
                            }
                        }
                        Label {
                            text: Config.baseUnit
                            color: Material.accentColor
                        }
                    }

                    RowLayout {
                        Layout.fillWidth: true
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
                }
            }

            RowLayout {
                Layout.columnSpan: 2
                Layout.fillWidth: true
                Layout.topMargin: constants.paddingSmall
                Label {
                    text: qsTr('Note')
                    color: Material.accentColor
                }
                Item { Layout.fillWidth: true }
                Label {
                    text: note.text.length + '/64'
                    font.pixelSize: constants.fontSizeSmall
                    color: commentValid ? constants.mutedForeground : constants.colorError
                }
            }
            ElTextArea {
                id: note
                Layout.columnSpan: 2
                Layout.fillWidth: true
                Layout.minimumHeight: 100
                wrapMode: TextEdit.Wrap
                placeholderText: qsTr('Enter an (optional) message for the receiver')
                color: commentValid ? Material.foreground : constants.colorError
            }
        }

        FlatButton {
            Layout.topMargin: constants.paddingLarge
            Layout.fillWidth: true
            text: qsTr('Request')
            icon.source: '../../icons/confirmed.png'
            enabled: valid
            onClicked: {
                invoiceParser.requestInvoiceFromOffer(note.text)
                dialog.close()
            }
        }
    }

}
