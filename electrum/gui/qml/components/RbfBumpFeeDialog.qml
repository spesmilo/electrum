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
    iconSource: Qt.resolvedUrl('../../icons/rocket.png')

    width: parent.width
    height: parent.height
    padding: 0

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
                text: qsTr('Increase your transaction\'s fee to improve its position in the mempool')
                wrapMode: Text.Wrap
            }

            Label {
                Layout.preferredWidth: 1
                Layout.fillWidth: true
                text: qsTr('Method')
                color: Material.accentColor
            }

            RowLayout {
                Layout.preferredWidth: 1
                Layout.fillWidth: true
                ElComboBox {
                    enabled: rbffeebumper.canChangeBumpMethod

                    textRole: 'text'
                    valueRole: 'value'

                    model: [
                        { text: qsTr('Preserve payment'), value: 'preserve_payment' },
                        { text: qsTr('Decrease payment'), value: 'decrease_payment' }
                    ]
                    onCurrentValueChanged: {
                        if (activeFocus)
                            rbffeebumper.bumpMethod = currentValue
                    }
                    Component.onCompleted: {
                        currentIndex = indexOfValue(rbffeebumper.bumpMethod)
                    }
                }
                Item { Layout.fillWidth: true;  Layout.preferredHeight: 1 }
            }

            Label {
                Layout.preferredWidth: 1
                Layout.fillWidth: true
                text: qsTr('Old fee')
                color: Material.accentColor
            }

            FormattedAmount {
                Layout.preferredWidth: 1
                Layout.fillWidth: true
                amount: rbffeebumper.oldfee
            }

            Label {
                text: qsTr('Old fee rate')
                color: Material.accentColor
            }

            RowLayout {
                Label {
                    id: oldfeeRate
                    text: rbffeebumper.oldfeeRate
                    font.family: FixedFont
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

            FormattedAmount {
                amount: rbffeebumper.fee
                valid: rbffeebumper.valid
            }

            Label {
                text: qsTr('Fee rate')
                color: Material.accentColor
            }

            RowLayout {
                Label {
                    id: feeRate
                    text: rbffeebumper.valid ? rbffeebumper.feeRate : ''
                    font.family: FixedFont
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
