import QtQuick
import QtQuick.Layouts
import QtQuick.Controls

import org.electrum 1.0

import "controls"

// "LNURL Withdraw request" of the Material 3 GUI, opened by PaymentFlow (requestDetails.onNeedsLNURLUserInput);
// replaces the classic LnurlWithdrawRequestDialog.
// repeats: components/LnurlWithdrawRequestDialog.qml:10-182 @ e6df7e1c8 (contract: wallet, requestDetails; the
// limits: walletCanReceive, provider min / max, effective min / max, insufficientLiquidity, liquidityWarning,
// amountValid / valid; walletCanReceive taken on completion and on lightningCanReceiveChanged unless busy; the
// three notices with their conditions and texts; provider, description; the amount field prefilled with the
// effective maximum and editable only when the provider's min and max differ; Withdraw... enabled when valid and
// not busy, it requests the withdrawal of the entered amount and closes).
// Look: an M3Dialog (M2-MAP F-2): notices as M3InfoText, provider and description as detail rows, the amount as
// M3AmountField. A fixed amount is shown read-only in both fields (the classic disables the bitcoin field and
// keeps it in the normal color).
// Strings carried over keep the translation context of LnurlWithdrawRequestDialog.qml.
M3Dialog {
    id: dialog

    title: qsTranslate('LnurlWithdrawRequestDialog', 'LNURL Withdraw request')
    iconSource: Qt.resolvedUrl('../../icons/m3/link.png')

    property var wallet: Daemon.currentWallet  // type: Wallet
    property var requestDetails  // type: RequestDetails

    property int walletCanReceive: 0
    property int providerMinWithdrawable: parseInt(requestDetails.lnurlData['min_withdrawable_sat'])
    property int providerMaxWithdrawable: parseInt(requestDetails.lnurlData['max_withdrawable_sat'])
    property int effectiveMinWithdrawable: Math.max(providerMinWithdrawable, 1)
    property int effectiveMaxWithdrawable: Math.min(providerMaxWithdrawable, walletCanReceive)
    property bool insufficientLiquidity: effectiveMinWithdrawable > walletCanReceive
    property bool liquidityWarning: providerMaxWithdrawable > walletCanReceive

    property bool amountValid: !dialog.insufficientLiquidity &&
        amountBtc.textAsSats.satsInt >= dialog.effectiveMinWithdrawable &&
        amountBtc.textAsSats.satsInt <= dialog.effectiveMaxWithdrawable
    property bool valid: amountValid

    // the dialog never grows past the free zone (keyboard included): the content scrolls instead
    // (centered: the same margin above and below, clear of the status bar and of the navigation bar; while the
    // keyboard is open the navigation bar is under it and the margin is smaller, the height is short then;
    // as PasswordDialog.qml)
    height: Math.min(implicitHeight, parent
        ? parent.height - 2 * (app.keyboardFreeZone.state != 'visible'
            ? m3.space24 + Math.max(app.statusBarHeight, app.navigationBarHeight)
            : m3.space8 + app.statusBarHeight)
        : implicitHeight)
    onClosed: destroy()

    Component.onCompleted: {
        dialog.walletCanReceive = wallet.lightningCanReceive.satsInt
    }

    Connections {
        // assign walletCanReceive directly to prevent a binding loop
        target: wallet
        function onLightningCanReceiveChanged() {
            if (!requestDetails.busy) {
                // don't assign while busy to prevent the view from changing while receiving
                // the incoming payment
                dialog.walletCanReceive = wallet.lightningCanReceive.satsInt
            }
        }
    }

    contentItem: Flickable {
        id: flick
        implicitHeight: form.implicitHeight
        contentHeight: form.implicitHeight
        clip: true
        interactive: height < contentHeight
        boundsBehavior: Flickable.StopAtBounds

        ColumnLayout {
            id: form
            width: flick.width
            spacing: m3.space12

            M3InfoText {
                Layout.fillWidth: true
                compact: true
                visible: dialog.insufficientLiquidity
                text: qsTranslate('LnurlWithdrawRequestDialog', 'Too little incoming liquidity to satisfy this withdrawal request.')
                          + '\n\n'
                          + qsTranslate('LnurlWithdrawRequestDialog', 'Can receive: %1')
                            .arg(Config.formatSats(dialog.walletCanReceive) + ' ' + Config.baseUnit)
                          + '\n'
                          + qsTranslate('LnurlWithdrawRequestDialog', 'Minimum withdrawal amount: %1')
                            .arg(Config.formatSats(dialog.providerMinWithdrawable) + ' ' + Config.baseUnit)
                          + '\n\n'
                          + qsTranslate('LnurlWithdrawRequestDialog', 'Do a submarine swap in the \'Channels\' tab to get more incoming liquidity.')
                iconStyle: M3InfoText.IconStyle.Error
            }

            M3InfoText {
                Layout.fillWidth: true
                compact: true
                visible: !dialog.insufficientLiquidity && dialog.providerMinWithdrawable != dialog.providerMaxWithdrawable
                text: qsTranslate('LnurlWithdrawRequestDialog', 'Amount must be between %1 and %2 %3')
                        .arg(Config.formatSats(dialog.effectiveMinWithdrawable))
                        .arg(Config.formatSats(dialog.effectiveMaxWithdrawable))
                        .arg(Config.baseUnit)
            }

            M3InfoText {
                Layout.fillWidth: true
                compact: true
                visible: dialog.liquidityWarning && !dialog.insufficientLiquidity
                text: qsTranslate('LnurlWithdrawRequestDialog', 'The maximum withdrawable amount (%1) is larger than what your channels can receive (%2).')
                            .arg(Config.formatSats(dialog.providerMaxWithdrawable) + ' ' + Config.baseUnit)
                            .arg(Config.formatSats(dialog.walletCanReceive) + ' ' + Config.baseUnit)
                        + ' '
                        + qsTranslate('LnurlWithdrawRequestDialog', 'You may need to do a submarine swap to increase your incoming liquidity.')
                iconStyle: M3InfoText.IconStyle.Warn
            }

            M3ListGroup {
                Layout.fillWidth: true
                color: m3.surfaceContainer

                M3DetailRow {
                    label: qsTranslate('LnurlWithdrawRequestDialog', 'Provider')
                    text: requestDetails.lnurlData['domain']
                }
                M3DetailRow {
                    visible: requestDetails.lnurlData['default_description']
                    label: qsTranslate('LnurlWithdrawRequestDialog', 'Description')
                    text: requestDetails.lnurlData['default_description']
                }
            }

            // the label 'Amount' of the classic form is the label of the field
            M3AmountField {
                id: amountBtc
                Layout.fillWidth: true
                text: Config.formatSatsForEditing(dialog.effectiveMaxWithdrawable)
                readOnly: !(!dialog.insufficientLiquidity && (dialog.providerMinWithdrawable != dialog.providerMaxWithdrawable))
            }
        }
    }

    buttons: [
        M3Button {
            variant: 'filled'
            text: qsTranslate('LnurlWithdrawRequestDialog', 'Withdraw...')
            icon.source: Qt.resolvedUrl('../../icons/m3/check.png')
            enabled: valid && !requestDetails.busy
            onClicked: {
                var satsAmount = amountBtc.textAsSats.satsInt;
                requestDetails.lnurlRequestWithdrawal(satsAmount);
                dialog.close();
            }
        }
    ]
}
