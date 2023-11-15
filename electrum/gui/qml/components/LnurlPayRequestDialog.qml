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

    property InvoiceParser invoiceParser

    padding: 0

    property bool commentValid: comment.text.length <= invoiceParser.lnurlData['comment_allowed']
    property bool amountValid: amountBtc.textAsSats.satsInt >= parseInt(invoiceParser.lnurlData['min_sendable_sat'])
        && amountBtc.textAsSats.satsInt <= parseInt(invoiceParser.lnurlData['max_sendable_sat'])
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

            InfoTextArea {
                Layout.columnSpan: 2
                Layout.fillWidth: true
                compact: true
                visible: invoiceParser.lnurlData['min_sendable_sat'] != invoiceParser.lnurlData['max_sendable_sat']
                text: qsTr('Amount must be between %1 and %2 %3').arg(Config.formatSats(invoiceParser.lnurlData['min_sendable_sat'])).arg(Config.formatSats(invoiceParser.lnurlData['max_sendable_sat'])).arg(Config.baseUnit)
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
                    text: Config.formatSatsForEditing(invoiceParser.lnurlData['min_sendable_sat'])
                    enabled: invoiceParser.lnurlData['min_sendable_sat'] != invoiceParser.lnurlData['max_sendable_sat']
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

        FlatButton {
            Layout.topMargin: constants.paddingLarge
            Layout.fillWidth: true
            text: qsTr('Pay')
            icon.source: '../../icons/confirmed.png'
            enabled: valid
            onClicked: {
                invoiceParser.lnurlGetInvoice(comment.text)
                dialog.close()
            }
        }
    }

}
