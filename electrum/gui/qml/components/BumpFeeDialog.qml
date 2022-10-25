import QtQuick 2.6
import QtQuick.Layouts 1.0
import QtQuick.Controls 2.14
import QtQuick.Controls.Material 2.0

import org.electrum 1.0

import "controls"

ElDialog {
    id: dialog

    required property string txid
    required property QtObject txfeebumper

    signal txaccepted

    title: qsTr('Bump Fee')

    width: parent.width
    height: parent.height
    padding: 0

    standardButtons: Dialog.Cancel

    modal: true
    parent: Overlay.overlay
    Overlay.modal: Rectangle {
        color: "#aa000000"
    }

    // function updateAmountText() {
    //     btcValue.text = Config.formatSats(finalizer.effectiveAmount, false)
    //     fiatValue.text = Daemon.fx.enabled
    //         ? '(' + Daemon.fx.fiatValue(finalizer.effectiveAmount, false) + ' ' + Daemon.fx.fiatCurrency + ')'
    //         : ''
    // }

    ColumnLayout {
        width: parent.width
        height: parent.height
        spacing: 0

        GridLayout {
            Layout.preferredWidth: parent.width
            Layout.leftMargin: constants.paddingLarge
            Layout.rightMargin: constants.paddingLarge
            columns: 2

            Label {
                text: qsTr('Old fee')
                color: Material.accentColor
            }

            RowLayout {
                Label {
                    id: oldfee
                    text: Config.formatSats(txfeebumper.oldfee)
                }

                Label {
                    text: Config.baseUnit
                    color: Material.accentColor
                }
            }

            Label {
                text: qsTr('Old fee rate')
                color: Material.accentColor
            }

            RowLayout {
                Label {
                    id: oldfeeRate
                    text: txfeebumper.oldfeeRate
                }

                Label {
                    text: 'sat/vB'
                    color: Material.accentColor
                }
            }

            // Label {
            //     id: amountLabel
            //     text: qsTr('Amount to send')
            //     color: Material.accentColor
            // }
            //
            // RowLayout {
            //     Layout.fillWidth: true
            //     Label {
            //         id: btcValue
            //         font.bold: true
            //     }
            //
            //     Label {
            //         text: Config.baseUnit
            //         color: Material.accentColor
            //     }
            //
            //     Label {
            //         id: fiatValue
            //         Layout.fillWidth: true
            //         font.pixelSize: constants.fontSizeMedium
            //     }
            //
            //     Component.onCompleted: updateAmountText()
            //     Connections {
            //         target: finalizer
            //         function onEffectiveAmountChanged() {
            //             updateAmountText()
            //         }
            //     }
            // }

            Label {
                text: qsTr('Mining fee')
                color: Material.accentColor
            }

            RowLayout {
                Label {
                    id: fee
                    text: txfeebumper.valid ? Config.formatSats(txfeebumper.fee) : ''
                }

                Label {
                    visible: txfeebumper.valid
                    text: Config.baseUnit
                    color: Material.accentColor
                }
            }

            Label {
                text: qsTr('Fee rate')
                color: Material.accentColor
            }

            RowLayout {
                Label {
                    id: feeRate
                    text: txfeebumper.valid ? txfeebumper.feeRate : ''
                }

                Label {
                    visible: txfeebumper.valid
                    text: 'sat/vB'
                    color: Material.accentColor
                }
            }

            Label {
                text: qsTr('Target')
                color: Material.accentColor
            }

            Label {
                id: targetdesc
                text: txfeebumper.target
            }

            Slider {
                id: feeslider
                leftPadding: constants.paddingMedium
                snapMode: Slider.SnapOnRelease
                stepSize: 1
                from: 0
                to: txfeebumper.sliderSteps
                onValueChanged: {
                    if (activeFocus)
                        txfeebumper.sliderPos = value
                }
                Component.onCompleted: {
                    value = txfeebumper.sliderPos
                }
                Connections {
                    target: txfeebumper
                    function onSliderPosChanged() {
                        feeslider.value = txfeebumper.sliderPos
                    }
                }
            }

            FeeMethodComboBox {
                id: target
                feeslider: txfeebumper
            }

            CheckBox {
                id: final_cb
                text: qsTr('Replace-by-Fee')
                Layout.columnSpan: 2
                checked: txfeebumper.rbf
                onCheckedChanged: {
                    if (activeFocus)
                        txfeebumper.rbf = checked
                }
            }

            InfoTextArea {
                Layout.columnSpan: 2
                Layout.preferredWidth: parent.width * 3/4
                Layout.alignment: Qt.AlignHCenter
                visible: txfeebumper.warning != ''
                text: txfeebumper.warning
                iconStyle: InfoTextArea.IconStyle.Warn
            }

            Label {
                visible: txfeebumper.valid
                text: qsTr('Outputs')
                Layout.columnSpan: 2
                color: Material.accentColor
            }

            Repeater {
                model: txfeebumper.valid ? txfeebumper.outputs : []
                delegate: TextHighlightPane {
                    Layout.columnSpan: 2
                    Layout.fillWidth: true
                    padding: 0
                    leftPadding: constants.paddingSmall
                    RowLayout {
                        width: parent.width
                        Label {
                            text: modelData.address
                            Layout.fillWidth: true
                            wrapMode: Text.Wrap
                            font.pixelSize: constants.fontSizeLarge
                            font.family: FixedFont
                            color: modelData.is_mine ? constants.colorMine : Material.foreground
                        }
                        Label {
                            text: Config.formatSats(modelData.value_sats)
                            font.pixelSize: constants.fontSizeMedium
                            font.family: FixedFont
                        }
                        Label {
                            text: Config.baseUnit
                            font.pixelSize: constants.fontSizeMedium
                            color: Material.accentColor
                        }
                    }
                }
            }
        }

        Item { Layout.fillHeight: true; Layout.preferredWidth: 1 }

        FlatButton {
            id: sendButton
            Layout.fillWidth: true
            text: qsTr('Ok')
            icon.source: '../../icons/confirmed.png'
            enabled: txfeebumper.valid
            onClicked: {
                txaccepted()
                dialog.close()
            }
        }
    }

}
