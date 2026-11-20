import QtQuick
import QtQuick.Layouts
import QtQuick.Controls
import QtQuick.Controls.Material

import org.electrum 1.0

import "controls"

// "Cancel Transaction" of the Material 3 GUI (a full-screen dialog, the result goes out by `accepted`).
// repeats: components/RbfCancelDialog.qml:10-173 (the contract `txcanceller`, the explanation, old fee
// and fee rate, the new fee picker without absolute fees, the warning, inputs and outputs without taps and
// sharing, Ok enabled while the canceller is valid -> doAccept()). Only the look differs.
// Strings keep the translation context of the classic file (qsTranslate('RbfCancelDialog', ...)).
M3FullScreenDialog {
    id: dialog

    required property QtObject txcanceller

    title: qsTranslate('RbfCancelDialog', 'Cancel Transaction')

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

                M3InfoText {
                    Layout.fillWidth: true
                    text: qsTranslate('RbfCancelDialog', 'Cancel an unconfirmed transaction by double-spending its inputs back to your wallet with a higher fee.')
                }

                M3ListGroup {
                    Layout.fillWidth: true

                    TxAmountRow {
                        label: qsTranslate('RbfCancelDialog', 'Old fee')
                        amount: dialog.txcanceller.oldfee
                    }

                    M3DetailRow {
                        label: qsTranslate('RbfCancelDialog', 'Old fee rate')
                        text: dialog.txcanceller.oldfeeRate + ' ' + UI_UNIT_NAME.FEERATE_SAT_PER_VB
                    }
                }

                M3SectionHeader {
                    Layout.fillWidth: true
                    Layout.bottomMargin: -m3.space8
                    leftPadding: 0
                    text: qsTranslate('RbfCancelDialog', 'New fee')
                }

                M3Card {
                    Layout.fillWidth: true

                    M3FeePicker {
                        id: feepicker
                        width: parent.width
                        finalizer: dialog.txcanceller
                        allowPickerAbsFees: false
                    }
                }

                M3InfoText {
                    Layout.fillWidth: true
                    iconStyle: M3InfoText.IconStyle.Warn
                    visible: dialog.txcanceller.warning != ''
                    text: dialog.txcanceller.warning
                }

                TxIoSection {
                    Layout.fillWidth: true
                    context: 'RbfCancelDialog'
                    shown: dialog.txcanceller.valid
                    inputs: dialog.txcanceller.inputs
                    outputs: dialog.txcanceller.outputs
                    allowClickInputs: false
                    allowShareOutputs: false
                    allowClickOutputs: false
                }
            }
        }

        TxDialogButtonBar {
            Layout.fillWidth: true
            text: qsTranslate('RbfCancelDialog', 'Ok')
            enabled: dialog.txcanceller.valid
            onClicked: dialog.doAccept()
        }
    }
}
