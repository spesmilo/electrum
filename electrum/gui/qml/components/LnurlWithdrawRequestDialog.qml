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

    property var wallet: Daemon.currentWallet  // type: Wallet
    property var requestDetails  // type: RequestDetails

    padding: 0
    needsSystemBarPadding: false

    property int walletCanReceive: 0
    property int providerMinWithdrawable: parseInt(requestDetails.lnurlData['min_withdrawable_msat'])
    property int providerMaxWithdrawable: parseInt(requestDetails.lnurlData['max_withdrawable_msat'])
    property int effectiveMinWithdrawable: Math.max(providerMinWithdrawable, 1)
    property int effectiveMaxWithdrawable: Math.min(providerMaxWithdrawable, walletCanReceive)
    property bool insufficientLiquidity: effectiveMinWithdrawable > walletCanReceive
    property bool liquidityWarning: providerMaxWithdrawable > walletCanReceive

    property bool amountValid: !dialog.insufficientLiquidity &&
        amountBtc.textAsSats.msatsInt >= dialog.effectiveMinWithdrawable &&
        amountBtc.textAsSats.msatsInt <= dialog.effectiveMaxWithdrawable
    property bool valid: amountValid

    Component.onCompleted: {
        dialog.walletCanReceive = wallet.lightningCanReceive.msatsInt
    }

    Connections {
        // assign walletCanReceive directly to prevent a binding loop
        target: wallet
        function onLightningCanReceiveChanged() {
            if (!requestDetails.busy) {
                // don't assign while busy to prevent the view from changing while receiving
                // the incoming payment
                dialog.walletCanReceive = wallet.lightningCanReceive.msatsInt
            }
        }
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
                visible: dialog.insufficientLiquidity
                text: qsTr('Too little incoming liquidity to satisfy this withdrawal request.')
                          + '\n\n'
                          + qsTr('Can receive: %1')
                            .arg(Config.formatMilliSats(dialog.walletCanReceive) + ' ' + Config.baseUnit)
                          + '\n'
                          + qsTr('Minimum withdrawal amount: %1')
                            .arg(Config.formatMilliSats(dialog.providerMinWithdrawable) + ' ' + Config.baseUnit)
                          + '\n\n'
                          + qsTr('Do a submarine swap in the \'Channels\' tab to get more incoming liquidity.')
                iconStyle: InfoTextArea.IconStyle.Error
                backgroundColor: constants.darkerDialogBackground
            }

            InfoTextArea {
                Layout.columnSpan: 2
                Layout.fillWidth: true
                compact: true
                visible: !dialog.insufficientLiquidity && dialog.providerMinWithdrawable != dialog.providerMaxWithdrawable
                text: qsTr('Amount must be between %1 and %2 %3')
                        .arg(Config.formatMilliSats(dialog.effectiveMinWithdrawable))
                        .arg(Config.formatMilliSats(dialog.effectiveMaxWithdrawable))
                        .arg(Config.baseUnit)
                backgroundColor: constants.darkerDialogBackground
            }

            InfoTextArea {
                Layout.columnSpan: 2
                Layout.fillWidth: true
                compact: true
                visible: dialog.liquidityWarning && !dialog.insufficientLiquidity
                text: qsTr('The maximum withdrawable amount (%1) is larger than what your channels can receive (%2).')
                            .arg(Config.formatMilliSats(dialog.providerMaxWithdrawable) + ' ' + Config.baseUnit)
                            .arg(Config.formatMilliSats(dialog.walletCanReceive) + ' ' + Config.baseUnit)
                        + ' '
                        + qsTr('You may need to do a submarine swap to increase your incoming liquidity.')
                iconStyle: InfoTextArea.IconStyle.Warn
                backgroundColor: constants.darkerDialogBackground
            }

            Label {
                text: qsTr('Provider')
                color: Material.accentColor
            }
            Label {
                Layout.fillWidth: true
                text: requestDetails.lnurlData['domain']
            }
            Label {
                text: qsTr('Description')
                color: Material.accentColor
                visible: requestDetails.lnurlData['default_description']
            }
            Label {
                Layout.fillWidth: true
                text: requestDetails.lnurlData['default_description']
                visible: requestDetails.lnurlData['default_description']
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
                    text: Config.formatMilliSatsForEditing(dialog.effectiveMaxWithdrawable)
                    enabled: !dialog.insufficientLiquidity && (dialog.providerMinWithdrawable != dialog.providerMaxWithdrawable)
                    color: Material.foreground // override gray-out on disabled
                    fiatfield: amountFiat
                    msatPrecision: true
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

        DialogButtonContainer {
            Layout.topMargin: constants.paddingLarge
            Layout.fillWidth: true
            FlatButton {
                Layout.fillWidth: true
                text: qsTr('Withdraw...')
                icon.source: '../../icons/confirmed.png'
                enabled: valid && !requestDetails.busy
                onClicked: {
                    var msatsAmount = amountBtc.textAsSats.msatsInt;
                    requestDetails.lnurlRequestWithdrawal(msatsAmount);
                    dialog.close();
                }
            }
        }
    }
}
