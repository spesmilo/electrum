import QtQuick
import QtQuick.Layouts
import QtQuick.Controls
import QtQuick.Controls.Material

import org.electrum 1.0

import "controls"

// Confirmation of an on-chain payment ("Transaction Fee") of the Material 3 GUI (M2-MAP F-1: full-screen dialog,
// created by PaymentFlow.payOnchain / startSweep and later by the channel opening, the result goes out by
// `accepted`). The API is that of the classic dialog: finalizer, satoshis, address, message, showOptions,
// amountLabelText, sendButtonText, title, accepted/rejected, doAccept/doReject.
// repeats: components/ConfirmTxDialog.qml:10-298 @ e6df7e1c8 (the API, address and amount copied to the finalizer,
// updateAmountText() with the effective amount while valid, the fee picker with the extra fee, the options:
// multiple change addresses and output value rounding with their helps, the warning, inputs and outputs without
// taps and sharing, the send button text by the wallet kind, enabled while valid -> doAccept(), doReject() when
// the dialog closes). Only the look differs, and the options are written on onToggled instead of
// onCheckedChanged + activeFocus (the same "user change only" rule for a row that takes no focus on press).
// Strings keep the translation context of the classic file (qsTranslate('ConfirmTxDialog', ...)).
M3FullScreenDialog {
    id: dialog

    required property QtObject finalizer
    required property var satoshis  // type: Amount
    property string address
    property string message
    property bool showOptions: true
    property alias amountLabelText: amountLabel.text
    property alias sendButtonText: sendBar.text

    title: qsTranslate('ConfirmTxDialog', 'Transaction Fee')
    iconSource: Qt.resolvedUrl('../../icons/m3/help.png')

    // copy these to finalizer
    onAddressChanged: finalizer.address = address
    onSatoshisChanged: finalizer.amount = satoshis

    function updateAmountText() {
        if (finalizer.valid) {
            btcValue.text = Config.formatSats(finalizer.effectiveAmount, false)
            fiatValue.text = Daemon.fx.enabled
                ? Daemon.fx.fiatValue(finalizer.effectiveAmount, false)
                : ''
        } else {
            btcValue.text = Config.formatSats(finalizer.amount, false)
            fiatValue.text = Daemon.fx.enabled
                ? Daemon.fx.fiatValue(finalizer.amount, false)
                : ''
        }
    }

    ColumnLayout {
        anchors.fill: parent
        spacing: 0

        Flickable {
            id: flickable
            Layout.fillWidth: true
            Layout.fillHeight: true
            clip: true
            contentHeight: content.implicitHeight + 2 * m3.space16
            interactive: height < contentHeight
            boundsBehavior: Flickable.StopAtBounds

            ColumnLayout {
                id: content
                readonly property int margin: m3.screenMargin(dialog.width)
                x: Math.max(margin, (flickable.width - width) / 2)
                y: m3.space16
                width: Math.min(m3.maxContentWidth, flickable.width - 2 * margin)
                spacing: m3.space16

                // --- amount (ConfirmTxDialog.qml:67-120) ---
                ColumnLayout {
                    Layout.fillWidth: true
                    spacing: m3.space4

                    M3Text {
                        id: amountLabel
                        Layout.fillWidth: true
                        horizontalAlignment: Text.AlignHCenter
                        role: 'labelLarge'
                        color: m3.surfaceVariantOn
                        wrapMode: Text.Wrap
                        text: qsTranslate('ConfirmTxDialog', 'Amount to send')
                    }

                    Row {
                        Layout.alignment: Qt.AlignHCenter
                        spacing: m3.space8
                        M3Text {
                            id: btcValue
                            role: 'headlineSmall'
                            font.weight: Font.Medium
                        }
                        M3Text {
                            anchors.baseline: btcValue.baseline
                            role: 'titleMedium'
                            color: m3.surfaceVariantOn
                            text: Config.baseUnit
                        }
                    }

                    Row {
                        Layout.alignment: Qt.AlignHCenter
                        visible: Daemon.fx.enabled
                        spacing: m3.space4
                        M3Text {
                            id: fiatValue
                            role: 'bodyMedium'
                            color: m3.surfaceVariantOn
                        }
                        M3Text {
                            role: 'bodyMedium'
                            color: m3.surfaceVariantOn
                            text: Daemon.fx.fiatCurrency
                        }
                    }

                    Component.onCompleted: updateAmountText()
                    Connections {
                        target: finalizer
                        function onEffectiveAmountChanged() {
                            updateAmountText()
                        }
                        function onValidChanged() {
                            updateAmountText()
                        }
                    }
                }

                // --- fee (ConfirmTxDialog.qml:122-149) ---
                M3SectionHeader {
                    Layout.fillWidth: true
                    Layout.bottomMargin: -m3.space8
                    leftPadding: 0
                    text: qsTranslate('ConfirmTxDialog', 'Fee')
                }

                M3Card {
                    Layout.fillWidth: true

                    M3FeePicker {
                        id: feepicker
                        width: parent.width
                        finalizer: dialog.finalizer

                        M3Text {
                            Layout.fillWidth: true
                            visible: !finalizer.extraFee.isEmpty
                            role: 'bodyMedium'
                            color: m3.surfaceVariantOn
                            wrapMode: Text.Wrap
                            text: qsTranslate('ConfirmTxDialog', 'Extra fee')
                        }

                        M3Amount {
                            Layout.alignment: Qt.AlignRight
                            visible: !finalizer.extraFee.isEmpty
                            amount: finalizer.extraFee
                            fiatRole: 'bodySmall'
                        }
                    }
                }

                // --- options (ConfirmTxDialog.qml:151-210) ---
                M3ListGroup {
                    Layout.fillWidth: true
                    visible: showOptions

                    M3ListItem {
                        id: optionstoggle
                        property bool collapsed: true
                        headline: qsTranslate('ConfirmTxDialog', 'Options')
                        onClicked: collapsed = !collapsed
                        trailing: Component {
                            M3Icon {
                                source: Qt.resolvedUrl('../../icons/m3/expand_more.png')
                                rotation: optionstoggle.collapsed ? 0 : 180
                            }
                        }
                    }

                    RowLayout {
                        Layout.fillWidth: true
                        visible: !optionstoggle.collapsed
                        spacing: 0

                        M3CheckRow {
                            Layout.fillWidth: true
                            text: qsTranslate('ConfirmTxDialog', 'Use multiple change addresses')
                            // the classic writes on a user change only (onCheckedChanged + activeFocus: a
                            // CheckBox takes the focus on press); a CheckDelegate takes no focus on press, so
                            // the user change is onToggled (emitted on a tap, a click or Space only)
                            onToggled: {
                                Daemon.currentWallet.multipleChange = checked
                                finalizer.doUpdate()
                            }
                            Component.onCompleted: {
                                checked = Daemon.currentWallet.multipleChange
                            }
                        }

                        M3HelpButton {
                            heading: qsTranslate('ConfirmTxDialog', 'Use multiple change addresses')
                            helptext: [qsTranslate('ConfirmTxDialog', 'In some cases, use up to 3 change addresses in order to break up large coin amounts and obfuscate the recipient address.'),
                                       qsTranslate('ConfirmTxDialog', 'This may result in higher transaction fees.')].join(' ')
                        }
                    }

                    RowLayout {
                        Layout.fillWidth: true
                        visible: !optionstoggle.collapsed
                        spacing: 0

                        M3CheckRow {
                            Layout.fillWidth: true
                            text: Config.shortDescFor('WALLET_COIN_CHOOSER_OUTPUT_ROUNDING')
                            // user change only: onToggled (see above)
                            onToggled: {
                                Config.outputValueRounding = checked
                                finalizer.doUpdate()
                            }
                            Component.onCompleted: {
                                checked = Config.outputValueRounding
                            }
                        }

                        M3HelpButton {
                            heading: Config.shortDescFor('WALLET_COIN_CHOOSER_OUTPUT_ROUNDING')
                            helptext: Config.longDescFor('WALLET_COIN_CHOOSER_OUTPUT_ROUNDING')
                        }
                    }
                }

                // --- warning (ConfirmTxDialog.qml:212-221) ---
                M3InfoText {
                    Layout.fillWidth: true
                    visible: finalizer.warning != ''
                    text: finalizer.warning
                    iconStyle: M3InfoText.IconStyle.Warn
                }

                // --- inputs and outputs (ConfirmTxDialog.qml:223-276) ---
                TxIoSection {
                    Layout.fillWidth: true
                    context: 'ConfirmTxDialog'
                    shown: finalizer.valid
                    inputs: finalizer.inputs
                    outputs: finalizer.outputs
                    allowClickInputs: false
                    allowShareOutputs: false
                    allowClickOutputs: false
                }
            }
        }

        // ConfirmTxDialog.qml:281-294
        TxDialogButtonBar {
            id: sendBar
            Layout.fillWidth: true
            text: (Daemon.currentWallet.isWatchOnly || !Daemon.currentWallet.canSignWithoutCosigner)
                    ? qsTranslate('ConfirmTxDialog', 'Finalize...')
                    : qsTranslate('ConfirmTxDialog', 'Pay...')
            icon.source: Qt.resolvedUrl('../../icons/m3/send.png')
            enabled: finalizer.valid
            onClicked: doAccept()
        }
    }

    onClosed: doReject()
}
