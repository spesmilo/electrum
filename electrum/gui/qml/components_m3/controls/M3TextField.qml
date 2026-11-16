import QtQuick
import QtQuick.Layouts
import QtQuick.Controls
import QtQuick.Controls.Material

// Outlined text field (Material containerStyle Outlined, Qt 6.5+) with a floating label and a
// supporting or error text below.
ColumnLayout {
    id: root

    property alias field: textField
    property alias text: textField.text
    property alias label: textField.placeholderText
    property alias readOnly: textField.readOnly
    property alias inputMethodHints: textField.inputMethodHints
    property alias validator: textField.validator
    property string supportingText
    property string errorText
    signal accepted()

    spacing: m3.space4

    TextField {
        id: textField
        Layout.fillWidth: true
        Material.containerStyle: Material.Outlined
        Material.accent: root.errorText !== '' ? m3.error : m3.primary
        font.pixelSize: m3.textStyle('bodyLarge').size
        color: m3.surfaceOn
        onAccepted: root.accepted()
    }

    M3Text {
        Layout.fillWidth: true
        Layout.leftMargin: m3.space16
        Layout.rightMargin: m3.space16
        visible: text !== ''
        role: 'bodySmall'
        wrapMode: Text.Wrap
        lineHeightMode: Text.ProportionalHeight
        lineHeight: 1.0
        color: root.errorText !== '' ? m3.error : m3.surfaceVariantOn
        text: root.errorText !== '' ? root.errorText : root.supportingText
    }
}
