import QtQuick
import QtQuick.Layouts
import QtQuick.Controls
import QtQuick.Controls.Material

import org.electrum 1.0

import "controls"

ElDialog {
    id: dialog

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
                        text: UI_UNIT_NAME.FEERATE_SAT_PER_VB
                        color: Material.accentColor
                    }
                }

                Label {
                    Layout.columnSpan: 2
                    Layout.topMargin: constants.paddingSmall
                    text: qsTr('New fee')
                    color: Material.accentColor
                }

                TextHighlightPane {
                    Layout.columnSpan: 2
                    Layout.fillWidth: true
                    height: feepicker.height

                    FeePicker {
                        id: feepicker
                        width: parent.width
                        finalizer: dialog.txcanceller

                    }
                }

                InfoTextArea {
                    Layout.columnSpan: 2
                    Layout.preferredWidth: parent.width * 3/4
                    Layout.alignment: Qt.AlignHCenter
                    Layout.topMargin: constants.paddingLarge
                    iconStyle: InfoTextArea.IconStyle.Warn
                    visible: txcanceller.warning != ''
                    text: txcanceller.warning
                }

                ToggleLabel {
                    id: inputs_label
                    Layout.columnSpan: 2
                    Layout.topMargin: constants.paddingMedium

                    visible: txcanceller.valid
                    labelText: qsTr('Inputs (%1)').arg(txcanceller.inputs.length)
                    color: Material.accentColor
                }

                Repeater {
                    model: inputs_label.collapsed || !inputs_label.visible
                        ? undefined
                        : txcanceller.inputs
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

                    visible: txcanceller.valid
                    labelText: qsTr('Outputs (%1)').arg(txcanceller.outputs.length)
                    color: Material.accentColor
                }

                Repeater {
                    model: outputs_label.collapsed || !outputs_label.visible
                        ? undefined
                        : txcanceller.outputs
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
            id: confirmButton
            Layout.fillWidth: true
            text: qsTr('Ok')
            icon.source: '../../icons/confirmed.png'
            enabled: txcanceller.valid
            onClicked: doAccept()
        }
    }
}
