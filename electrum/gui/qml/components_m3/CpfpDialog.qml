import QtQuick
import QtQuick.Layouts
import QtQuick.Controls
import QtQuick.Controls.Material

import org.electrum 1.0

import "controls"

// "Bump Fee" by CPFP (child pays for parent) of the Material 3 GUI (M2-MAP F-1: full-screen dialog, the result
// goes out by `accepted`).
// repeats: components/CpfpBumpFeeDialog.qml:10-231 @ e6df7e1c8 (the contract `cpfpfeebumper`, the explanation and
// its help, the child fee info without the picker, the totals: size, fee, fee rate, the picker without fee rates
// and without tx info, the warning, inputs and outputs without taps and sharing, Ok enabled while the bumper is
// valid -> doAccept()). Only the look differs.
// Strings keep the translation context of the classic file (qsTranslate('CpfpBumpFeeDialog', ...)).
M3FullScreenDialog {
    id: dialog

    required property QtObject cpfpfeebumper

    title: qsTranslate('CpfpBumpFeeDialog', 'Bump Fee')
    iconSource: Qt.resolvedUrl('../../icons/m3/speed.png')

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

                // CpfpBumpFeeDialog.qml:283-293
                M3Card {
                    Layout.fillWidth: true
                    color: m3.secondaryContainer
                    contentColor: m3.secondaryContainerOn
                    topPadding: m3.space8
                    bottomPadding: m3.space8
                    rightPadding: m3.space4

                    RowLayout {
                        width: parent.width
                        spacing: m3.space8

                        M3Text {
                            Layout.fillWidth: true
                            role: 'bodyMedium'
                            color: m3.secondaryContainerOn
                            wrapMode: Text.Wrap
                            lineHeightMode: Text.ProportionalHeight
                            lineHeight: 1.0
                            text: qsTranslate('CpfpBumpFeeDialog', 'A CPFP is a transaction that sends an unconfirmed output back to yourself, with a high fee.')
                        }

                        M3HelpButton {
                            icon.color: m3.secondaryContainerOn
                            heading: qsTranslate('CpfpBumpFeeDialog', 'CPFP - Child Pays For Parent')
                            helptext: qsTranslate('CpfpBumpFeeDialog', 'A CPFP is a transaction that sends an unconfirmed output back to yourself, with a high fee. The goal is to have miners confirm the parent transaction in order to get the fee attached to the child transaction.')
                            + '<br/><br/>' + qsTranslate('CpfpBumpFeeDialog', 'The proposed fee is computed using your fee/vkB settings, applied to the total size of both child and parent transactions. After you broadcast a CPFP transaction, it is normal to see a new unconfirmed transaction in your history.')
                        }
                    }
                }

                // CpfpBumpFeeDialog.qml:295-316
                M3SectionHeader {
                    Layout.fillWidth: true
                    Layout.bottomMargin: -m3.space8
                    leftPadding: 0
                    text: qsTranslate('CpfpBumpFeeDialog', 'Child tx fee')
                }

                M3Card {
                    Layout.fillWidth: true

                    M3FeePicker {
                        id: feepicker_childinfo
                        width: parent.width
                        finalizer: dialog.cpfpfeebumper
                        targetLabel: qsTranslate('CpfpBumpFeeDialog', 'Target total')
                        feeLabel: qsTranslate('CpfpBumpFeeDialog', 'Fee for child')
                        feeRateLabel: qsTranslate('CpfpBumpFeeDialog', 'Fee rate for child')
                        showPicker: false
                    }
                }

                // CpfpBumpFeeDialog.qml:318-393
                M3SectionHeader {
                    Layout.fillWidth: true
                    Layout.bottomMargin: -m3.space8
                    leftPadding: 0
                    text: qsTranslate('CpfpBumpFeeDialog', 'Total')
                }

                M3ListGroup {
                    Layout.fillWidth: true

                    M3DetailRow {
                        label: qsTranslate('CpfpBumpFeeDialog', 'Total size')
                        text: dialog.cpfpfeebumper.valid
                            ? dialog.cpfpfeebumper.totalSize + ' ' + UI_UNIT_NAME.TXSIZE_VBYTES
                            : ''
                    }

                    TxAmountRow {
                        label: qsTranslate('CpfpBumpFeeDialog', 'Total fee')
                        amount: dialog.cpfpfeebumper.totalFee
                        valid: dialog.cpfpfeebumper.valid
                    }

                    M3DetailRow {
                        label: qsTranslate('CpfpBumpFeeDialog', 'Total fee rate')
                        text: dialog.cpfpfeebumper.valid
                            ? dialog.cpfpfeebumper.totalFeeRate + ' ' + UI_UNIT_NAME.FEERATE_SAT_PER_VB
                            : ''
                    }

                    Item {
                        Layout.fillWidth: true
                        implicitHeight: feepicker.implicitHeight + 2 * m3.space8

                        M3FeePicker {
                            id: feepicker
                            anchors.left: parent.left
                            anchors.right: parent.right
                            anchors.leftMargin: m3.space16
                            anchors.rightMargin: m3.space16
                            anchors.verticalCenter: parent.verticalCenter
                            finalizer: dialog.cpfpfeebumper
                            showTxInfo: false
                            allowPickerFeeRates: false
                        }
                    }
                }

                M3InfoText {
                    Layout.fillWidth: true
                    visible: dialog.cpfpfeebumper.warning != ''
                    text: dialog.cpfpfeebumper.warning
                    iconStyle: M3InfoText.IconStyle.Warn
                }

                TxIoSection {
                    Layout.fillWidth: true
                    context: 'CpfpBumpFeeDialog'
                    shown: dialog.cpfpfeebumper.valid
                    inputs: dialog.cpfpfeebumper.inputs
                    outputs: dialog.cpfpfeebumper.outputs
                    allowClickInputs: false
                    allowShareOutputs: false
                    allowClickOutputs: false
                }
            }
        }

        TxDialogButtonBar {
            Layout.fillWidth: true
            text: qsTranslate('CpfpBumpFeeDialog', 'Ok')
            enabled: dialog.cpfpfeebumper.valid
            onClicked: dialog.doAccept()
        }
    }
}
