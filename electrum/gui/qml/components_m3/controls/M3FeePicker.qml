import QtQuick
import QtQuick.Layouts
import QtQuick.Controls
import QtQuick.Controls.Material

import org.electrum 1.0

// Fee picker of the Material 3 GUI, same API as the classic FeePicker: `finalizer` (a TxFeeSlider: TxFinalizer,
// TxRbfFeeBumper, TxCanceller, TxCpfpFeeBumper, SweepFinalizer), the labels, the show/allow switches and extra
// rows as children (the default property: pairs of label + value, laid out in two columns after the fee rows).
// repeats: components/controls/FeePicker.qml:8-197 (the fee and fee rate rows, the target, the
// slider and its bindings to finalizer.sliderPos/sliderSteps, the manual fee rate and absolute fee fields with
// their validators and colors) and components/controls/FeeMethodComboBox.qml:6-27 (the four methods,
// set on user choice only).
// Differences: Material 3 look; the method is a segmented button instead of the combo box (the same model and
// the same "only on user action" rule: M3SegmentedButton.activated); the value rows are label (left) and value
// (right) rows; the manual fields are outlined text fields with the unit beside them.
// Strings keep the translation context of the classic files (qsTranslate('FeePicker' / 'FeeMethodComboBox', ...)).
Item {
    id: root

    required property QtObject finalizer

    default property alias additionalItems: extraLayout.data

    property string targetLabel: qsTranslate('FeePicker', 'Target')
    property string feeLabel: qsTranslate('FeePicker', 'Mining fee')
    property string feeRateLabel: qsTranslate('FeePicker', 'Fee rate')

    property bool showTxInfo: true
    property bool showPicker: true
    property bool allowPickerAbsFees: true
    property bool allowPickerFeeRates: true

    property bool manualFeeEntry: finalizer.method == FeeSlider.FSMethod.MANUAL

    implicitHeight: rootLayout.implicitHeight
    implicitWidth: rootLayout.implicitWidth
    Layout.fillWidth: true

    ColumnLayout {
        id: rootLayout
        width: parent.width
        spacing: m3.space8

        // fee and fee rate
        RowLayout {
            Layout.fillWidth: true
            visible: root.showTxInfo
            spacing: m3.space8
            M3Text {
                Layout.fillWidth: true
                Layout.alignment: Qt.AlignTop
                role: 'bodyMedium'
                color: m3.surfaceVariantOn
                wrapMode: Text.Wrap
                text: root.feeLabel
            }
            M3Amount {
                Layout.alignment: Qt.AlignTop | Qt.AlignRight
                visible: root.finalizer.valid
                amount: root.finalizer.fee
                fiatRole: 'bodySmall'
            }
        }

        RowLayout {
            Layout.fillWidth: true
            visible: root.showTxInfo
            spacing: m3.space8
            M3Text {
                Layout.fillWidth: true
                role: 'bodyMedium'
                color: m3.surfaceVariantOn
                wrapMode: Text.Wrap
                text: root.feeRateLabel
            }
            M3Text {
                id: feeRate
                role: 'bodyLarge'
                text: root.finalizer.valid ? root.finalizer.feeRate : ''
            }
            M3Text {
                role: 'bodyLarge'
                color: m3.surfaceVariantOn
                text: root.finalizer.valid ? UI_UNIT_NAME.FEERATE_SAT_PER_VBYTE : ''
            }
        }

        // extra rows of the caller (e.g. "Extra fee" of ConfirmTxDialog)
        GridLayout {
            id: extraLayout
            Layout.fillWidth: true
            visible: children.length > 0
            columns: 2
            columnSpacing: m3.space8
            rowSpacing: m3.space8
        }

        // target of the slider
        RowLayout {
            Layout.fillWidth: true
            Layout.topMargin: root.showTxInfo ? m3.space8 : 0
            visible: root.showPicker && !root.manualFeeEntry
            spacing: m3.space8
            M3Text {
                Layout.fillWidth: true
                role: 'bodyMedium'
                color: m3.surfaceVariantOn
                wrapMode: Text.Wrap
                text: root.targetLabel
            }
            M3Text {
                role: 'labelLarge'
                color: m3.primary
                text: root.finalizer.target
            }
        }

        Slider {
            id: feeslider
            Layout.fillWidth: true
            visible: root.showPicker
            enabled: !root.manualFeeEntry

            snapMode: Slider.SnapOnRelease
            stepSize: 1
            from: 0
            to: root.finalizer.sliderSteps

            onValueChanged: {
                if (activeFocus)
                    root.finalizer.sliderPos = value
            }
            Component.onCompleted: {
                value = root.finalizer.sliderPos
            }
            Connections {
                target: root.finalizer
                function onSliderPosChanged() {
                    feeslider.value = root.finalizer.sliderPos
                }
            }
        }

        // FeeMethodComboBox.qml:14-26
        M3SegmentedButton {
            id: target
            Layout.fillWidth: true
            visible: root.showPicker
            model: [
                { text: qsTranslate('FeeMethodComboBox', 'ETA'), value: FeeSlider.FSMethod.ETA },
                { text: qsTranslate('FeeMethodComboBox', 'Mempool'), value: FeeSlider.FSMethod.MEMPOOL },
                { text: qsTranslate('FeeMethodComboBox', 'Feerate'), value: FeeSlider.FSMethod.FEERATE },
                { text: qsTranslate('FeeMethodComboBox', 'Manual'), value: FeeSlider.FSMethod.MANUAL }
            ]
            currentValue: root.finalizer.method
            onActivated: (value) => {
                root.finalizer.method = value
            }
        }

        // manual fee rate
        RowLayout {
            Layout.fillWidth: true
            Layout.topMargin: m3.space8
            visible: root.showPicker && root.manualFeeEntry && root.allowPickerFeeRates
            spacing: m3.space8

            M3TextField {
                id: rate
                Layout.fillWidth: true
                label: qsTranslate('FeePicker', 'Rate')
                text: root.finalizer.userFeerate
                field.color: root.finalizer.isUserFeerateLast ? m3.surfaceOn : m3.primary
                inputMethodHints: Qt.ImhDigitsOnly
                validator: RegularExpressionValidator {
                    regularExpression: /^[0-9]*\.[0-9]?$/
                }
                Connections {
                    target: rate.field
                    function onTextEdited() {
                        root.finalizer.userFeerate = rate.text
                    }
                }
            }

            M3Text {
                role: 'bodyLarge'
                color: m3.surfaceVariantOn
                text: UI_UNIT_NAME.FEERATE_SAT_PER_VBYTE
            }
        }

        // manual absolute fee
        RowLayout {
            Layout.fillWidth: true
            Layout.topMargin: m3.space8
            visible: root.showPicker && root.manualFeeEntry && root.allowPickerAbsFees
            spacing: m3.space8

            M3TextField {
                id: absolute
                Layout.fillWidth: true
                label: qsTranslate('FeePicker', 'Total')
                text: root.finalizer.userFee
                field.color: root.finalizer.isUserFeerateLast ? m3.primary : m3.surfaceOn
                inputMethodHints: Qt.ImhDigitsOnly
                validator: RegularExpressionValidator {
                    regularExpression: /^[0-9]*$/
                }
                Connections {
                    target: absolute.field
                    function onTextEdited() {
                        root.finalizer.userFee = absolute.text
                    }
                }
            }

            M3Text {
                role: 'bodyLarge'
                color: m3.surfaceVariantOn
                text: UI_UNIT_NAME.FIXED_SAT
            }
        }
    }
}
