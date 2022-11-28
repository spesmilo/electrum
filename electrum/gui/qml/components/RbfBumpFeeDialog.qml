import QtQuick 2.6
import QtQuick.Layouts 1.0
import QtQuick.Controls 2.14
import QtQuick.Controls.Material 2.0

import org.electrum 1.0

import "controls"

ElDialog {
    id: dialog

    required property string txid
    required property QtObject rbffeebumper

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
                    text: Config.formatSats(rbffeebumper.oldfee)
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
                    text: rbffeebumper.oldfeeRate
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
                    text: rbffeebumper.valid ? Config.formatSats(rbffeebumper.fee) : ''
                }

                Label {
                    visible: rbffeebumper.valid
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
                    text: rbffeebumper.valid ? rbffeebumper.feeRate : ''
                }

                Label {
                    visible: rbffeebumper.valid
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
                text: rbffeebumper.target
            }

            Slider {
                id: feeslider
                leftPadding: constants.paddingMedium
                snapMode: Slider.SnapOnRelease
                stepSize: 1
                from: 0
                to: rbffeebumper.sliderSteps
                onValueChanged: {
                    if (activeFocus)
                        rbffeebumper.sliderPos = value
                }
                Component.onCompleted: {
                    value = rbffeebumper.sliderPos
                }
                Connections {
                    target: rbffeebumper
                    function onSliderPosChanged() {
                        feeslider.value = rbffeebumper.sliderPos
                    }
                }
            }

            FeeMethodComboBox {
                id: target
                feeslider: rbffeebumper
            }

            CheckBox {
                id: final_cb
                text: qsTr('Replace-by-Fee')
                Layout.columnSpan: 2
                checked: rbffeebumper.rbf
                onCheckedChanged: {
                    if (activeFocus)
                        rbffeebumper.rbf = checked
                }
            }

            InfoTextArea {
                Layout.columnSpan: 2
                Layout.preferredWidth: parent.width * 3/4
                Layout.alignment: Qt.AlignHCenter
                visible: rbffeebumper.warning != ''
                text: rbffeebumper.warning
                iconStyle: InfoTextArea.IconStyle.Warn
            }

            Label {
                visible: rbffeebumper.valid
                text: qsTr('Outputs')
                Layout.columnSpan: 2
                color: Material.accentColor
            }

            Repeater {
                model: rbffeebumper.valid ? rbffeebumper.outputs : []
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
            enabled: rbffeebumper.valid
            onClicked: {
                txaccepted()
                dialog.close()
            }
        }
    }

    Connections {
        target: rbffeebumper
        function onTxMined() {
            dialog.close()
        }
    }
}
