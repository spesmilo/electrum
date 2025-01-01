import QtQuick
import QtQuick.Layouts
import QtQuick.Controls
import QtQuick.Controls.Material

import org.electrum 1.0

import "controls"

ElDialog {
    id: dialog

    required property QtObject rbffeebumper

    title: qsTr('Bump Fee')
    iconSource: Qt.resolvedUrl('../../icons/rocket.png')

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
                    text: qsTr('Move the slider to increase your transaction\'s fee. This will improve its position in the mempool')
                }

                Label {
                    Layout.fillWidth: true
                    text: qsTr('Method')
                    color: Material.accentColor
                }

                RowLayout {
                    ElComboBox {
                        id: bumpMethodComboBox

                        textRole: 'text'
                        valueRole: 'value'

                        model: rbffeebumper.bumpMethodsAvailable
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
                    text: qsTr('Old fee')
                    color: Material.accentColor
                }

                FormattedAmount {
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
                        finalizer: dialog.rbffeebumper

                    }
                }

                ToggleLabel {
                    id: optionstoggle
                    Layout.columnSpan: 2
                    labelText: qsTr('Options')
                    color: Material.accentColor
                }

                TextHighlightPane {
                    Layout.columnSpan: 2
                    Layout.fillWidth: true
                    visible: !optionstoggle.collapsed
                    height: optionslayout.height

                    GridLayout {
                        id: optionslayout
                        width: parent.width
                        columns: 2

                        ElCheckBox {
                            Layout.fillWidth: true
                            text: qsTr('Enable output value rounding')
                            onCheckedChanged: {
                                if (activeFocus) {
                                    Config.outputValueRounding = checked
                                    rbffeebumper.doUpdate()
                                }
                            }
                            Component.onCompleted: {
                                checked = Config.outputValueRounding
                            }
                        }

                        HelpButton {
                            heading: qsTr('Enable output value rounding')
                            helptext: qsTr('In some cases, use up to 3 change addresses in order to break up large coin amounts and obfuscate the recipient address.')
                                    + ' ' + qsTr('This may result in higher transactions fees.')
                        }
                    }
                }

                InfoTextArea {
                    Layout.columnSpan: 2
                    Layout.preferredWidth: parent.width * 3/4
                    Layout.alignment: Qt.AlignHCenter
                    Layout.topMargin: constants.paddingLarge
                    iconStyle: InfoTextArea.IconStyle.Warn
                    visible: rbffeebumper.warning != ''
                    text: rbffeebumper.warning
                }

                ToggleLabel {
                    id: inputs_label
                    Layout.columnSpan: 2
                    Layout.topMargin: constants.paddingMedium

                    visible: rbffeebumper.valid
                    labelText: qsTr('Inputs (%1)').arg(rbffeebumper.inputs.length)
                    color: Material.accentColor
                }

                Repeater {
                    model: inputs_label.collapsed || !inputs_label.visible
                        ? undefined
                        : rbffeebumper.inputs
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

                    visible: rbffeebumper.valid
                    labelText: qsTr('Outputs (%1)').arg(rbffeebumper.outputs.length)
                    color: Material.accentColor
                }

                Repeater {
                    model: outputs_label.collapsed || !outputs_label.visible
                        ? undefined
                        : rbffeebumper.outputs
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
            text: qsTr('Ok')
            icon.source: '../../icons/confirmed.png'
            enabled: rbffeebumper.valid
            onClicked: doAccept()
        }
    }

    Connections {
        target: rbffeebumper
        function onTxMined() {
            dialog.doReject()
        }
    }
}
