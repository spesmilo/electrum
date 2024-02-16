import QtQuick
import QtQuick.Layouts
import QtQuick.Controls
import QtQuick.Controls.Material

import org.electrum 1.0

Item {
    id: root

    required property QtObject finalizer

    default property alias additionalItems: rootLayout.children

    property string targetLabel: qsTr('Target')
    property string feeLabel: qsTr('Mining fee')
    property string feeRateLabel: qsTr('Fee rate')

    property bool showTxInfo: true
    property bool showPicker: true

    implicitHeight: rootLayout.height

    GridLayout {
        id: rootLayout
        width: parent.width
        columns: 2

        Label {
            Layout.fillWidth: true
            Layout.preferredWidth: 1
            text: feeLabel
            color: Material.accentColor
            visible: showTxInfo
        }

        FormattedAmount {
            Layout.fillWidth: true
            Layout.preferredWidth: 2
            amount: finalizer.fee
            valid: finalizer.valid
            visible: showTxInfo
        }

        Label {
            Layout.fillWidth: true
            Layout.preferredWidth: 1
            text: feeRateLabel
            color: Material.accentColor
            visible: showTxInfo
        }

        RowLayout {
            Layout.fillWidth: true
            Layout.preferredWidth: 2
            visible: showTxInfo
            Label {
                id: feeRate
                text: finalizer.valid ? finalizer.feeRate : ''
                font.family: FixedFont
            }

            Label {
                Layout.fillWidth: true
                text: finalizer.valid ? UI_UNIT_NAME.FEERATE_SAT_PER_VBYTE : ''
                color: Material.accentColor
            }
        }

        Label {
            Layout.fillWidth: true
            Layout.preferredWidth: 1
            text: targetLabel
            color: Material.accentColor
            visible: showPicker
        }

        Label {
            Layout.fillWidth: true
            Layout.preferredWidth: 2
            text: finalizer.target
            visible: showPicker
        }

        RowLayout {
            Layout.columnSpan: 2
            Layout.fillWidth: true
            visible: showPicker

            Slider {
                id: feeslider
                Layout.fillWidth: true
                leftPadding: constants.paddingMedium

                snapMode: Slider.SnapOnRelease
                stepSize: 1
                from: 0
                to: finalizer.sliderSteps

                onValueChanged: {
                    if (activeFocus)
                        finalizer.sliderPos = value
                }
                Component.onCompleted: {
                    value = finalizer.sliderPos
                }
                Connections {
                    target: finalizer
                    function onSliderPosChanged() {
                        feeslider.value = finalizer.sliderPos
                    }
                }
            }

            FeeMethodComboBox {
                id: target
                feeslider: finalizer
            }
        }
    }
}
