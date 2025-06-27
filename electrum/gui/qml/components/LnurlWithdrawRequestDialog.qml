import QtQuick
import QtQuick.Layouts
import QtQuick.Controls
import QtQuick.Controls.Material

import org.electrum 1.0

import "controls"

ElDialog {
    id: dialog

    title: qsTr('LNURL Withdraw request')
    iconSource: '../../../icons/link.png'

    property InvoiceParser invoiceParser

    padding: 0

    property int walletCanReceive: invoiceParser.wallet.lightningCanReceive.satsInt
    property int providerMinWithdrawable: parseInt(invoiceParser.lnurlData['min_withdrawable_sat'])
    property int providerMaxWithdrawable: parseInt(invoiceParser.lnurlData['max_withdrawable_sat'])
    property int effectiveMinWithdrawable: Math.max(providerMinWithdrawable, 1)
    property int effectiveMaxWithdrawable: Math.min(providerMaxWithdrawable, walletCanReceive)
    property bool insufficientLiquidity: effectiveMinWithdrawable > walletCanReceive
    property bool liquidityWarning: providerMaxWithdrawable > walletCanReceive

    property bool amountValid: !dialog.insufficientLiquidity &&
        amountBtc.textAsSats.satsInt >= dialog.effectiveMinWithdrawable &&
        amountBtc.textAsSats.satsInt <= dialog.effectiveMaxWithdrawable
    property bool valid: amountValid

    ColumnLayout {
        width: parent.width

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
                visible: dialog.insufficientLiquidity
                text: qsTr('Too little incoming liquidity to satisfy this withdrawal request.')
                          + '\n\n'
                          + qsTr('Can receive: %1')
                            .arg(Config.formatSats(dialog.walletCanReceive) + ' ' + Config.baseUnit)
                          + '\n'
                          + qsTr('Minimum withdrawal amount: %1')
                            .arg(Config.formatSats(dialog.providerMinWithdrawable) + ' ' + Config.baseUnit)
                          + '\n\n'
                          + qsTr('Do a submarine swap in the \'Channels\' tab to get more incoming liquidity.')
                iconStyle: InfoTextArea.IconStyle.Error
            }

            InfoTextArea {
                Layout.columnSpan: 2
                Layout.fillWidth: true
                compact: true
                visible: !dialog.insufficientLiquidity && dialog.providerMinWithdrawable != dialog.providerMaxWithdrawable
                text: qsTr('Amount must be between %1 and %2 %3')
                .arg(Config.formatSats(dialog.effectiveMinWithdrawable))
                .arg(Config.formatSats(dialog.effectiveMaxWithdrawable))
                .arg(Config.baseUnit)
            }

            InfoTextArea {
                Layout.columnSpan: 2
                Layout.fillWidth: true
                compact: true
                visible: dialog.liquidityWarning && !dialog.insufficientLiquidity
                text: qsTr('The maximum withdrawable amount (%1) is larger than what your channels can receive (%2).')
                            .arg(Config.formatSats(dialog.providerMaxWithdrawable) + ' ' + Config.baseUnit)
                            .arg(Config.formatSats(dialog.walletCanReceive) + ' ' + Config.baseUnit)
                        + ' '
                        + qsTr('You may need to do a submarine swap to increase your incoming liquidity.')
                iconStyle: InfoTextArea.IconStyle.Warn
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
                visible: invoiceParser.lnurlData['default_description']
            }
            Label {
                Layout.fillWidth: true
                text: invoiceParser.lnurlData['default_description']
                visible: invoiceParser.lnurlData['default_description']
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
                    Layout.preferredWidth: rootLayout.width / 3
                    text: Config.formatSatsForEditing(dialog.effectiveMaxWithdrawable)
                    enabled: !dialog.insufficientLiquidity && (dialog.providerMinWithdrawable != dialog.providerMaxWithdrawable)
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
                    enabled: !dialog.insufficientLiquidity && (dialog.providerMinWithdrawable != dialog.providerMaxWithdrawable)
                    color: Material.foreground
                }
                Label {
                    text: Daemon.fx.fiatCurrency
                    color: Material.accentColor
                }
            }
        }

        FlatButton {
            Layout.topMargin: constants.paddingLarge
            Layout.fillWidth: true
            text: qsTr('Withdraw...')
            icon.source: '../../icons/confirmed.png'
            enabled: valid
            onClicked: {
                invoiceParser.lnurlRequestWithdrawal()
                dialog.close()
            }
        }
    }

}
