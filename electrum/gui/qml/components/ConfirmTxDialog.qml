import QtQuick
import QtQuick.Layouts
import QtQuick.Controls
import QtQuick.Controls.Material

import org.electrum 1.0

import "controls"

ElDialog {
    id: dialog

    required property QtObject finalizer
    required property Amount satoshis
    property string address
    property string message
    property alias amountLabelText: amountLabel.text
    property alias sendButtonText: sendButton.text

    title: qsTr('Transaction Fee')

    // copy these to finalizer
    onAddressChanged: finalizer.address = address
    onSatoshisChanged: finalizer.amount = satoshis

    width: parent.width
    height: parent.height
    padding: 0

    function updateAmountText() {
        btcValue.text = Config.formatSats(finalizer.effectiveAmount, false)
        fiatValue.text = Daemon.fx.enabled
            ? '(' + Daemon.fx.fiatValue(finalizer.effectiveAmount, false) + ' ' + Daemon.fx.fiatCurrency + ')'
            : ''
    }

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

                Label {
                    id: amountLabel
                    Layout.fillWidth: true
                    Layout.minimumWidth: implicitWidth
                    text: qsTr('Amount to send')
                    color: Material.accentColor
                }
                RowLayout {
                    Layout.fillWidth: true
                    Label {
                        id: btcValue
                        font.bold: true
                        font.family: FixedFont
                    }

                    Label {
                        text: Config.baseUnit
                        color: Material.accentColor
                    }

                    Label {
                        id: fiatValue
                        Layout.fillWidth: true
                        font.pixelSize: constants.fontSizeMedium
                    }

                    Component.onCompleted: updateAmountText()
                    Connections {
                        target: finalizer
                        function onEffectiveAmountChanged() {
                            updateAmountText()
                        }
                    }
                }

                Label {
                    text: qsTr('Mining fee')
                    color: Material.accentColor
                }

                FormattedAmount {
                    amount: finalizer.fee
                }

                Label {
                    visible: !finalizer.extraFee.isEmpty
                    text: qsTr('Extra fee')
                    color: Material.accentColor
                }

                FormattedAmount {
                    visible: !finalizer.extraFee.isEmpty
                    amount: finalizer.extraFee
                }

                Label {
                    text: qsTr('Fee rate')
                    color: Material.accentColor
                }

                RowLayout {
                    Label {
                        id: feeRate
                        text: finalizer.feeRate
                        font.family: FixedFont
                    }

                    Label {
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

                InfoTextArea {
                    Layout.columnSpan: 2
                    Layout.fillWidth: true
                    Layout.topMargin: constants.paddingLarge
                    Layout.bottomMargin: constants.paddingLarge
                    visible: finalizer.warning != ''
                    text: finalizer.warning
                    iconStyle: InfoTextArea.IconStyle.Warn
                }

                Label {
                    text: qsTr('Outputs')
                    Layout.columnSpan: 2
                    color: Material.accentColor
                }

                Repeater {
                    model: finalizer.outputs
                    delegate: TxOutput {
                        Layout.columnSpan: 2
                        Layout.fillWidth: true

                        allowShare: false
                        model: modelData
                    }
                }
            }
        }

        FlatButton {
            id: sendButton
            Layout.fillWidth: true
            text: (Daemon.currentWallet.isWatchOnly || !Daemon.currentWallet.canSignWithoutCosigner)
                    ? qsTr('Finalize')
                    : qsTr('Pay')
            icon.source: '../../icons/confirmed.png'
            enabled: finalizer.valid
            onClicked: doAccept()
        }
    }

    onClosed: doReject()
}
