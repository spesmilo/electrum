import QtQuick
import QtQuick.Layouts
import QtQuick.Controls

import "controls"

// Inputs and outputs of a transaction for the transaction screens of the Material 3 GUI (TxDetailsPage,
// BumpFeeDialog, CpfpDialog, CancelTxDialog, ConfirmTxDialog): two collapsible lists, "Inputs (n)" and
// "Outputs (n)", collapsed at first.
// repeats: the ToggleLabel + Repeater pairs of components/TxDetails.qml:326-369, RbfBumpFeeDialog.qml:173-222,
// CpfpBumpFeeDialog.qml:165-214, RbfCancelDialog.qml:106-155, ConfirmTxDialog.qml:223-276 and
// components/controls/ToggleLabel.qml:5-17 (collapsed by default, a tap toggles): while collapsed or hidden
// (`shown` false: TxDetails `!error`, the dialogs `valid`) the Repeater has no model, as in the classic files.
// `context` is the classic file the caller replaces: the headings "Inputs (%1)" / "Outputs (%1)" keep its
// translation context.
ColumnLayout {
    id: root

    property string context: 'TxDetails'
    property bool shown: true
    property var inputs: []
    property var outputs: []
    // TxInput.allowClick; TxOutput.allowShare, allowClickAddress
    property bool allowClickInputs: true
    property bool allowShareOutputs: true
    property bool allowClickOutputs: true

    Layout.fillWidth: true
    visible: shown
    spacing: m3.space8

    ToggleRow {
        id: inputsToggle
        headline: qsTranslate(root.context, 'Inputs (%1)').arg(root.inputs.length)
    }

    M3ListGroup {
        Layout.fillWidth: true
        visible: !inputsToggle.collapsed && root.inputs.length > 0

        Repeater {
            model: inputsToggle.collapsed || !root.shown
                ? undefined
                : root.inputs
            delegate: M3TxInput {
                Layout.fillWidth: true
                allowClick: root.allowClickInputs
                idx: index
                model: modelData
            }
        }
    }

    ToggleRow {
        id: outputsToggle
        headline: qsTranslate(root.context, 'Outputs (%1)').arg(root.outputs.length)
    }

    M3ListGroup {
        Layout.fillWidth: true
        visible: !outputsToggle.collapsed && root.outputs.length > 0

        Repeater {
            model: outputsToggle.collapsed || !root.shown
                ? undefined
                : root.outputs
            delegate: M3TxOutput {
                Layout.fillWidth: true
                allowShare: root.allowShareOutputs
                allowClickAddress: root.allowClickOutputs
                idx: index
                model: modelData
            }
        }
    }

    // the classic ToggleLabel: a heading row with a chevron, collapsed at first
    component ToggleRow: M3ListItem {
        id: toggle
        property bool collapsed: true
        Layout.fillWidth: true
        onClicked: collapsed = !collapsed
        background: Rectangle {
            radius: m3.radiusL
            color: toggle.down
                ? Qt.rgba(m3.surfaceOn.r, m3.surfaceOn.g, m3.surfaceOn.b, m3.statePressed)
                : toggle.hovered || toggle.visualFocus
                    ? Qt.rgba(m3.surfaceOn.r, m3.surfaceOn.g, m3.surfaceOn.b, m3.stateHover)
                    : m3.surfaceContainerLow
        }
        trailing: Component {
            M3Icon {
                source: Qt.resolvedUrl('../../icons/m3/expand_more.png')
                rotation: toggle.collapsed ? 0 : 180
            }
        }
    }
}
