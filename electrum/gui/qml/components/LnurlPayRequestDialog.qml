import QtQuick
import QtQuick.Layouts
import QtQuick.Controls
import QtQuick.Controls.Material

import org.electrum 1.0

import "controls"

ElDialog {
    id: dialog

    title: qsTr('LNURL Payment request')
    iconSource: '../../../icons/link.png'

    property var invoiceParser  // type: InvoiceParser

    padding: 0
    needsSystemBarPadding: false

    property bool commentValid: comment.text.length <= invoiceParser.lnurlData['comment_allowed']
    property bool amountValid: false
    property bool valid: commentValid && amountValid

    function isValidAmount() {
        return amountBtc.textAsSats.gte(invoiceParser.lnurlData['min_sendable_msat'])
            && amountBtc.textAsSats.lte(invoiceParser.lnurlData['max_sendable_msat'])
    }

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

            InfoTextArea {
                Layout.columnSpan: 2
                Layout.fillWidth: true
                compact: true
                visible: !invoiceParser.lnurlData['min_sendable_msat'].eq(invoiceParser.lnurlData['max_sendable_msat'])
                text: qsTr('Amount must be between %1 and %2 %3')
                    .arg(Config.formatMilliSats(invoiceParser.lnurlData['min_sendable_msat']))
                    .arg(Config.formatMilliSats(invoiceParser.lnurlData['max_sendable_msat']))
                    .arg(Config.baseUnit)
            }

            Label {
                text: qsTr('Provider')
                color: Material.accentColor
            }
            Label {
                Layout.fillWidth: true
                text: invoiceParser.lnurlData['domain']
            }
            Label {
                text: qsTr('Description')
                color: Material.accentColor
            }
            Label {
                Layout.fillWidth: true
                text: invoiceParser.lnurlData['metadata_plaintext']
                wrapMode: Text.Wrap
            }

            Label {
                text: qsTr('Amount')
                color: Material.accentColor
            }

            RowLayout {
                Layout.fillWidth: true
                BtcField {
                    id: amountBtc
                    Layout.preferredWidth: rootLayout.width /3
                    text: Config.formatMilliSatsForEditing(invoiceParser.lnurlData['min_sendable_msat'])
                    enabled: !invoiceParser.lnurlData['min_sendable_msat'].eq(invoiceParser.lnurlData['max_sendable_msat'])
                    color: Material.foreground // override gray-out on disabled
                    fiatfield: amountFiat
                    msatPrecision: true
                    onValueChanged: {
                        invoiceParser.amountOverride = textAsSats
                        dialog.amountValid = isValidAmount()
                    }
                }
                Label {
                    text: Config.baseUnit
                    color: Material.accentColor
                }
            }

            Item { visible: Daemon.fx.enabled; Layout.preferredWidth: 1; Layout.preferredHeight: 1 }

            RowLayout {
                visible: Daemon.fx.enabled
                FiatField {
                    id: amountFiat
                    Layout.preferredWidth: rootLayout.width / 3
                    btcfield: amountBtc
                }
                Label {
                    text: Daemon.fx.fiatCurrency
                    color: Material.accentColor
                }
            }

            Label {
                Layout.columnSpan: 2
                visible: invoiceParser.lnurlData['comment_allowed'] > 0
                text: qsTr('Message')
                color: Material.accentColor
            }
            ElTextArea {
                id: comment
                Layout.columnSpan: 2
                Layout.fillWidth: true
                Layout.minimumHeight: 160
                visible: invoiceParser.lnurlData['comment_allowed'] > 0
                wrapMode: TextEdit.Wrap
                placeholderText: qsTr('Enter an (optional) message for the receiver')
                color: text.length > invoiceParser.lnurlData['comment_allowed'] ? constants.colorError : Material.foreground
            }

            Label {
                Layout.columnSpan: 2
                Layout.leftMargin: constants.paddingLarge
                visible: invoiceParser.lnurlData['comment_allowed'] > 0
                text: qsTr('%1 characters remaining').arg(Math.max(0, (invoiceParser.lnurlData['comment_allowed'] - comment.text.length) ))
                color: constants.mutedForeground
                font.pixelSize: constants.fontSizeSmall
            }
        }

        DialogButtonContainer {
            Layout.topMargin: constants.paddingLarge
            Layout.fillWidth: true
            FlatButton {
                Layout.fillWidth: true
                text: qsTr('Pay...')
                icon.source: '../../icons/confirmed.png'
                enabled: valid
                onClicked: {
                    invoiceParser.lnurlGetInvoice(comment.text)
                    dialog.close()
                }
            }
        }
    }

}
