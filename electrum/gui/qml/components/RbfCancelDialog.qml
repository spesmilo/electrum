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

    title: qsTr('Cancel Transaction')

    width: parent.width
    height: parent.height
    padding: 0

    ColumnLayout {
        anchors.fill: parent
        spacing: 0

        Flickable {
            Layout.fillWidth: true
            Layout.fillHeight: true

            leftMargin: constants.paddingLarge
            rightMargin: constants.paddingLarge

            contentHeight: rootLayout.height
            clip: true
            interactive: height < contentHeight

            GridLayout {
                id: rootLayout
                width: parent.width
                columns: 2

                InfoTextArea {
                    Layout.columnSpan: 2
                    Layout.fillWidth: true
                    Layout.bottomMargin: constants.paddingLarge
                    text: qsTr('Cancel an unconfirmed transaction by double-spending its inputs back to your wallet with a higher fee.')
                }

                Label {
                    text: qsTr('Old fee')
                    color: Material.accentColor
                }

                FormattedAmount {
                    amount: txcanceller.oldfee
                }

                Label {
                    text: qsTr('Old fee rate')
                    color: Material.accentColor
                }

                RowLayout {
                    Label {
                        id: oldfeeRate
                        text: txcanceller.oldfeeRate
                        font.family: FixedFont
                    }

                    Label {
                        text: 'sat/vB'
                        color: Material.accentColor
                    }
                }

                Label {
                    text: qsTr('New fee')
                    color: Material.accentColor
                }

                FormattedAmount {
                    amount: txcanceller.fee
                    valid: txcanceller.valid
                }

                Label {
                    text: qsTr('New fee rate')
                    color: Material.accentColor
                }

                RowLayout {
                    Label {
                        id: feeRate
                        text: txcanceller.valid ? txcanceller.feeRate : ''
                        font.family: FixedFont
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

                RowLayout {
                    Layout.columnSpan: 2
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

                Label {
                    Layout.columnSpan: 2
                    Layout.fillWidth: true
                    visible: txcanceller.warning != ''
                    text: txcanceller.warning
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
        }

        FlatButton {
            id: confirmButton
            Layout.fillWidth: true
            text: qsTr('Ok')
            icon.source: '../../icons/confirmed.png'
            enabled: txcanceller.valid
            onClicked: doAccept()
        }
    }

    Connections {
        target: txcanceller
        function onTxMined() {
            dialog.doReject()
        }
    }
}
