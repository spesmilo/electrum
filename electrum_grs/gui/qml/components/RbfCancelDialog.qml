import QtQuick 2.6
import QtQuick.Layouts 1.0
import QtQuick.Controls 2.14
import QtQuick.Controls.Material 2.0

import org.electrum 1.0

import "controls"

ElDialog {
    id: dialog

    required property string txid
    required property QtObject txcanceller

    signal txaccepted

    title: qsTr('Cancel Transaction')

    width: parent.width
    height: parent.height
    padding: 0

    standardButtons: Dialog.Cancel

    modal: true
    parent: Overlay.overlay
    Overlay.modal: Rectangle {
        color: "#aa000000"
    }

    ColumnLayout {
        anchors.fill: parent
        spacing: 0

        GridLayout {
            Layout.preferredWidth: parent.width
            Layout.leftMargin: constants.paddingLarge
            Layout.rightMargin: constants.paddingLarge
            columns: 2

            Label {
                Layout.columnSpan: 2
                Layout.fillWidth: true
                text: qsTr('Cancel an unconfirmed RBF transaction by double-spending its inputs back to your wallet with a higher fee.')
                wrapMode: Text.Wrap
            }

            Label {
                text: qsTr('Old fee')
                color: Material.accentColor
            }

            RowLayout {
                Label {
                    id: oldfee
                    text: Config.formatSats(txcanceller.oldfee)
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
                    text: txcanceller.oldfeeRate
                }

                Label {
                    text: 'sat/vB'
                    color: Material.accentColor
                }
            }

            Label {
                text: qsTr('Mining fee')
                color: Material.accentColor
            }

            RowLayout {
                Label {
                    id: fee
                    text: txcanceller.valid ? Config.formatSats(txcanceller.fee) : ''
                }

                Label {
                    visible: txcanceller.valid
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
                    text: txcanceller.valid ? txcanceller.feeRate : ''
                }

                Label {
                    visible: txcanceller.valid
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
                text: txcanceller.target
            }

            Slider {
                id: feeslider
                leftPadding: constants.paddingMedium
                snapMode: Slider.SnapOnRelease
                stepSize: 1
                from: 0
                to: txcanceller.sliderSteps
                onValueChanged: {
                    if (activeFocus)
                        txcanceller.sliderPos = value
                }
                Component.onCompleted: {
                    value = txcanceller.sliderPos
                }
                Connections {
                    target: txcanceller
                    function onSliderPosChanged() {
                        feeslider.value = txcanceller.sliderPos
                    }
                }
            }

            FeeMethodComboBox {
                id: target
                feeslider: txcanceller
            }

            CheckBox {
                id: final_cb
                text: qsTr('Replace-by-Fee')
                Layout.columnSpan: 2
                checked: txcanceller.rbf
                onCheckedChanged: {
                    if (activeFocus)
                        txcanceller.rbf = checked
                }
            }

            InfoTextArea {
                Layout.columnSpan: 2
                Layout.preferredWidth: parent.width * 3/4
                Layout.alignment: Qt.AlignHCenter
                visible: txcanceller.warning != ''
                text: txcanceller.warning
                iconStyle: InfoTextArea.IconStyle.Warn
            }

            Label {
                visible: txcanceller.valid
                text: qsTr('Outputs')
                Layout.columnSpan: 2
                color: Material.accentColor
            }

            Repeater {
                model: txcanceller.valid ? txcanceller.outputs : []
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
            id: confirmButton
            Layout.fillWidth: true
            text: qsTr('Ok')
            icon.source: '../../icons/confirmed.png'
            enabled: txcanceller.valid
            onClicked: {
                txaccepted()
                dialog.close()
            }
        }
    }

    Connections {
        target: txcanceller
        function onTxMined() {
            dialog.close()
        }
    }
}
