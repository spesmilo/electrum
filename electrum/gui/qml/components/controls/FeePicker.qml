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
        }

        FormattedAmount {
            Layout.fillWidth: true
            Layout.preferredWidth: 2
            amount: finalizer.fee
            valid: finalizer.valid
        }

        Label {
            Layout.fillWidth: true
            Layout.preferredWidth: 1
            text: feeRateLabel
            color: Material.accentColor
        }

        RowLayout {
            Layout.fillWidth: true
            Layout.preferredWidth: 2
            Label {
                id: feeRate
                text: finalizer.valid ? finalizer.feeRate : ''
                font.family: FixedFont
            }

            Label {
                text: finalizer.valid ? UI_UNIT_NAME.FEERATE_SAT_PER_VBYTE : ''
                color: Material.accentColor
            }
        }

        Label {
            Layout.fillWidth: true
            Layout.preferredWidth: 1
            text: targetLabel
            color: Material.accentColor
        }

        Label {
            Layout.fillWidth: true
            Layout.preferredWidth: 2
            id: targetdesc
            text: finalizer.target
        }

        RowLayout {
            Layout.columnSpan: 2
            Layout.fillWidth: true

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
