import QtQuick
import QtQuick.Layouts
import QtQuick.Controls
import QtQuick.Controls.Material

import org.electrum 1.0

import "controls"

// "Bump Fee" (RBF) of the Material 3 GUI (a full-screen dialog, the result goes out by `accepted`).
// repeats: components/RbfBumpFeeDialog.qml:10-240 (the contract `rbffeebumper`, the explanation, the
// bump method chosen by the user, old fee and fee rate, the new fee picker without absolute fees, the output
// value rounding option with its help, the warning, inputs and outputs without taps and sharing, Ok enabled
// while the bumper is valid -> doAccept()). Only the look differs, and the rounding option is written on
// onToggled instead of onCheckedChanged + activeFocus (the same "user change only" rule for a row that takes
// no focus on press).
// Strings keep the translation context of the classic file (qsTranslate('RbfBumpFeeDialog', ...)).
M3FullScreenDialog {
    id: dialog

    required property QtObject rbffeebumper

    title: qsTranslate('RbfBumpFeeDialog', 'Bump Fee')
    iconSource: Qt.resolvedUrl('../../icons/m3/speed.png')

    ColumnLayout {
        anchors.fill: parent
        spacing: 0

        Flickable {
            id: flickable
            Layout.fillWidth: true
            Layout.fillHeight: true
            clip: true
            contentHeight: content.implicitHeight + 2 * m3.space16
            interactive: height < contentHeight
            boundsBehavior: Flickable.StopAtBounds

            ColumnLayout {
                id: content
                readonly property int margin: m3.screenMargin(dialog.width)
                x: Math.max(margin, (flickable.width - width) / 2)
                y: m3.space16
                width: Math.min(m3.maxContentWidth, flickable.width - 2 * margin)
                spacing: m3.space16

                M3InfoText {
                    Layout.fillWidth: true
                    text: qsTranslate('RbfBumpFeeDialog', 'Move the slider to increase your transaction\'s fee. This will improve its position in the mempool')
                }

                M3ListGroup {
                    Layout.fillWidth: true

                    // RbfBumpFeeDialog.qml:52-75: set on user choice only
                    M3SelectRow {
                        headline: qsTranslate('RbfBumpFeeDialog', 'Method')
                        model: dialog.rbffeebumper.bumpMethodsAvailable
                        currentValue: dialog.rbffeebumper.bumpMethod
                        onSelected: (value) => {
                            dialog.rbffeebumper.bumpMethod = value
                        }
                    }

                    TxAmountRow {
                        label: qsTranslate('RbfBumpFeeDialog', 'Old fee')
                        amount: dialog.rbffeebumper.oldfee
                    }

                    M3DetailRow {
                        label: qsTranslate('RbfBumpFeeDialog', 'Old fee rate')
                        text: dialog.rbffeebumper.oldfeeRate + ' ' + UI_UNIT_NAME.FEERATE_SAT_PER_VB
                    }
                }

                M3SectionHeader {
                    Layout.fillWidth: true
                    Layout.bottomMargin: -m3.space8
                    leftPadding: 0
                    text: qsTranslate('RbfBumpFeeDialog', 'New fee')
                }

                M3Card {
                    Layout.fillWidth: true

                    M3FeePicker {
                        id: feepicker
                        width: parent.width
                        finalizer: dialog.rbffeebumper
                        allowPickerAbsFees: false
                    }
                }

                // RbfBumpFeeDialog.qml:124-161 (Options)
                M3ListGroup {
                    Layout.fillWidth: true

                    M3ListItem {
                        id: optionstoggle
                        property bool collapsed: true
                        headline: qsTranslate('RbfBumpFeeDialog', 'Options')
                        onClicked: collapsed = !collapsed
                        trailing: Component {
                            M3Icon {
                                source: Qt.resolvedUrl('../../icons/m3/expand_more.png')
                                rotation: optionstoggle.collapsed ? 0 : 180
                            }
                        }
                    }

                    RowLayout {
                        Layout.fillWidth: true
                        visible: !optionstoggle.collapsed
                        spacing: 0

                        M3CheckRow {
                            Layout.fillWidth: true
                            text: Config.shortDescFor('WALLET_COIN_CHOOSER_OUTPUT_ROUNDING')
                            // the classic writes on a user change only (onCheckedChanged + activeFocus: a
                            // CheckBox takes the focus on press); a CheckDelegate takes no focus on press, so
                            // the user change is onToggled (emitted on a tap, a click or Space only)
                            onToggled: {
                                Config.outputValueRounding = checked
                                dialog.rbffeebumper.doUpdate()
                            }
                            Component.onCompleted: {
                                checked = Config.outputValueRounding
                            }
                        }

                        M3HelpButton {
                            heading: Config.shortDescFor('WALLET_COIN_CHOOSER_OUTPUT_ROUNDING')
                            helptext: Config.longDescFor('WALLET_COIN_CHOOSER_OUTPUT_ROUNDING')
                        }
                    }
                }

                M3InfoText {
                    Layout.fillWidth: true
                    iconStyle: M3InfoText.IconStyle.Warn
                    visible: dialog.rbffeebumper.warning != ''
                    text: dialog.rbffeebumper.warning
                }

                TxIoSection {
                    Layout.fillWidth: true
                    context: 'RbfBumpFeeDialog'
                    shown: dialog.rbffeebumper.valid
                    inputs: dialog.rbffeebumper.inputs
                    outputs: dialog.rbffeebumper.outputs
                    allowClickInputs: false
                    allowShareOutputs: false
                    allowClickOutputs: false
                }
            }
        }

        TxDialogButtonBar {
            Layout.fillWidth: true
            text: qsTranslate('RbfBumpFeeDialog', 'Ok')
            enabled: dialog.rbffeebumper.valid
            onClicked: dialog.doAccept()
        }
    }
}
