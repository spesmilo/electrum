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
    iconSource: Qt.resolvedUrl('../../icons/question.png')

    // copy these to finalizer
    onAddressChanged: finalizer.address = address
    onSatoshisChanged: finalizer.amount = satoshis

    width: parent.width
    height: parent.height
    padding: 0

    function updateAmountText() {
        btcValue.text = Config.formatSats(finalizer.effectiveAmount, false)
        fiatValue.text = Daemon.fx.enabled
            ? Daemon.fx.fiatValue(finalizer.effectiveAmount, false)
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
                    Layout.columnSpan: 2
                    text: qsTr('Amount to send')
                    color: Material.accentColor
                }

                TextHighlightPane {
                    Layout.columnSpan: 2
                    Layout.fillWidth: true
                    GridLayout {
                        columns: 2
                        Label {
                            id: btcValue
                            Layout.alignment: Qt.AlignRight
                            font.pixelSize: constants.fontSizeXLarge
                            font.family: FixedFont
                            font.bold: true
                        }

                        Label {
                            Layout.fillWidth: true
                            text: Config.baseUnit
                            color: Material.accentColor
                            font.pixelSize: constants.fontSizeXLarge
                        }

                        Label {
                            id: fiatValue
                            Layout.alignment: Qt.AlignRight
                            visible: Daemon.fx.enabled
                            font.pixelSize: constants.fontSizeMedium
                            color: constants.mutedForeground
                        }

                        Label {
                            Layout.fillWidth: true
                            visible: Daemon.fx.enabled
                            text: Daemon.fx.fiatCurrency
                            font.pixelSize: constants.fontSizeMedium
                            color: constants.mutedForeground
                        }
                        Component.onCompleted: updateAmountText()
                        Connections {
                            target: finalizer
                            function onEffectiveAmountChanged() {
                                updateAmountText()
                            }
                        }
                    }
                }

                Label {
                    Layout.columnSpan: 2
                    text: qsTr('Fee')
                    color: Material.accentColor
                }

                TextHighlightPane {
                    Layout.columnSpan: 2
                    Layout.fillWidth: true
                    height: feepicker.height

                    FeePicker {
                        id: feepicker
                        width: parent.width
                        finalizer: dialog.finalizer

                        Label {
                            visible: !finalizer.extraFee.isEmpty
                            text: qsTr('Extra fee')
                            color: Material.accentColor
                        }

                        FormattedAmount {
                            visible: !finalizer.extraFee.isEmpty
                            amount: finalizer.extraFee
                        }
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

                ToggleLabel {
                    id: inputs_label
                    Layout.columnSpan: 2
                    Layout.topMargin: constants.paddingMedium

                    labelText: qsTr('Inputs (%1)').arg(finalizer.inputs.length)
                    color: Material.accentColor
                }

                Repeater {
                    model: inputs_label.collapsed
                        ? undefined
                        : finalizer.inputs
                    delegate: TxInput {
                        Layout.columnSpan: 2
                        Layout.fillWidth: true

                        idx: index
                        model: modelData
                    }
                }

                ToggleLabel {
                    id: outputs_label
                    Layout.columnSpan: 2
                    Layout.topMargin: constants.paddingMedium

                    labelText: qsTr('Outputs (%1)').arg(finalizer.outputs.length)
                    color: Material.accentColor
                }

                Repeater {
                    model: outputs_label.collapsed
                        ? undefined
                        : finalizer.outputs
                    delegate: TxOutput {
                        Layout.columnSpan: 2
                        Layout.fillWidth: true

                        allowShare: false
                        allowClickAddress: false

                        idx: index
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
