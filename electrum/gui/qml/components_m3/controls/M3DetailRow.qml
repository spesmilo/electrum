import QtQuick
import QtQuick.Layouts
import QtQuick.Controls

// Detail row of the Material 3 GUI (M2-MAP F-4): label (bodySmall, onSurfaceVariant) above the value
// (bodyLarge); addresses, txids, invoices and keys (`monospace: true`) in the fixed font, wrapping anywhere.
// On the right the optional share button (`shareable`: share glyph, opens app.genericShareDialog with
// `shareTitle` and `shareText`, which also offers "Copy"), and optional `actions` (icon buttons, e.g. edit)
// before it. Replaces the classic grid of Label + TextHighlightPane + ToolButton
// (components/controls/TextHighlightPane.qml, DialogHighlightPane.qml @ e6df7e1c8, as used by TxDetails,
// LightningPaymentDetails, ChannelDetails, AddressDetails, WalletDetails, NetworkOverview).
// Set `customShare` to handle shareClicked() yourself instead of the dialog.
Item {
    id: root

    property string label
    property string text
    property bool monospace: false
    property int textFormat: Text.PlainText
    property color valueColor: m3.surfaceOn
    property bool shareable: false
    property string shareTitle: label
    property string shareText: text
    property bool customShare: false
    property list<Item> actions

    signal shareClicked()

    Layout.fillWidth: true
    implicitWidth: row.implicitWidth + 2 * m3.space16
    implicitHeight: Math.max(56, row.implicitHeight + 2 * m3.space8)

    function share() {
        root.shareClicked()
        if (root.customShare)
            return
        var dialog = app.genericShareDialog.createObject(app, { title: root.shareTitle, text: root.shareText })
        dialog.open()
    }

    RowLayout {
        id: row
        anchors.left: parent.left
        anchors.right: parent.right
        anchors.leftMargin: m3.space16
        anchors.rightMargin: root.shareable || root.actions.length ? m3.space4 : m3.space16
        anchors.verticalCenter: parent.verticalCenter
        spacing: m3.space8

        ColumnLayout {
            Layout.fillWidth: true
            Layout.alignment: Qt.AlignVCenter
            spacing: 2

            M3Text {
                Layout.fillWidth: true
                visible: root.label !== ''
                role: 'bodySmall'
                color: m3.surfaceVariantOn
                wrapMode: Text.Wrap
                lineHeightMode: Text.ProportionalHeight
                lineHeight: 1.0
                text: root.label
            }
            M3Text {
                Layout.fillWidth: true
                role: 'bodyLarge'
                color: root.valueColor
                font.family: root.monospace ? FixedFont : m3TextFont.font.family
                wrapMode: root.monospace ? Text.WrapAnywhere : Text.Wrap
                lineHeightMode: Text.ProportionalHeight
                lineHeight: 1.0
                textFormat: root.textFormat
                text: root.text
            }
        }

        Row {
            Layout.alignment: Qt.AlignVCenter
            visible: root.actions.length > 0
            children: root.actions
        }

        M3IconButton {
            Layout.alignment: Qt.AlignVCenter
            visible: root.shareable
            tooltip: qsTr('Share')
            icon.source: Qt.resolvedUrl('../../../icons/m3/share.png')
            onClicked: root.share()
        }
    }

    // the default family of a label, to switch back from the fixed font
    M3Text { id: m3TextFont; visible: false }
}
