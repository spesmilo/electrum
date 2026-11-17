import QtQuick
import QtQuick.Layouts
import QtQuick.Controls

import "controls"

// Detail row with an amount, for the transaction screens of the Material 3 GUI: the label (bodySmall) above
// the amount in the base unit and its fiat value beside it (M3Amount). The Material 3 form of the classic
// Label + FormattedAmount pairs (components/TxDetails.qml:108-159, RbfBumpFeeDialog.qml:77-84,
// RbfCancelDialog.qml:49-56, CpfpBumpFeeDialog.qml:348-360, LightningPaymentDetails.qml:181-203 @ e6df7e1c8);
// a row of M3ListGroup like M3DetailRow. `valid` false shows no amount, as FormattedAmount.valid.
Item {
    id: root

    property string label
    property var amount
    property int timestamp: 0
    property bool valid: true

    Layout.fillWidth: true
    implicitHeight: Math.max(56, layout.implicitHeight + 2 * m3.space8)

    ColumnLayout {
        id: layout
        anchors.left: parent.left
        anchors.right: parent.right
        anchors.leftMargin: m3.space16
        anchors.rightMargin: m3.space16
        anchors.verticalCenter: parent.verticalCenter
        spacing: 2

        M3Text {
            Layout.fillWidth: true
            role: 'bodySmall'
            color: m3.surfaceVariantOn
            wrapMode: Text.Wrap
            lineHeightMode: Text.ProportionalHeight
            lineHeight: 1.0
            text: root.label
        }
        M3Amount {
            visible: root.valid && root.amount !== undefined && root.amount !== null
            amount: root.amount
            timestamp: root.timestamp
            fiatBelow: false
            fiatRole: 'bodyMedium'
        }
        // the empty value of an invalid amount keeps the height of the row
        M3Text {
            visible: !(root.valid && root.amount !== undefined && root.amount !== null)
            role: 'bodyLarge'
            text: ' '
        }
    }
}
