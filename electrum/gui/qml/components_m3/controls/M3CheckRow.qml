import QtQuick
import QtQuick.Layouts
import QtQuick.Controls
import QtQuick.Controls.Material

// List row with a checkbox on the right (the same row as M3RadioRow), for an option that is confirmed rather
// than switched (a switch is M3SwitchRow). A CheckDelegate, so it keeps the API of the classic ElCheckBox
// (components/controls/ElCheckBox.qml @ e6df7e1c8: a CheckBox whose text wraps): text, checked, checkState,
// tristate, toggled(), clicked(); a tap anywhere on the row toggles it, as a tap on the classic checkbox.
// Added: `headline` (= text), `supporting` (second line, bodyMedium), `leadingIcon` (24 dp); height 56 / 72;
// state layer as M3ListItem; disabled rows show their content at 0.38 opacity.
CheckDelegate {
    id: root

    property string headline
    property string supporting
    property url leadingIcon

    readonly property string _headline: headline !== '' ? headline : text

    text: headline
    Layout.fillWidth: true
    implicitHeight: Math.max(supporting === '' ? 56 : 72, layout.implicitHeight + 2 * 8)
    leftPadding: m3.space16
    rightPadding: m3.space16
    topPadding: 8
    bottomPadding: 8
    font.pixelSize: m3.textStyle('bodyLarge').size

    background: Rectangle {
        color: root.down
            ? Qt.rgba(m3.surfaceOn.r, m3.surfaceOn.g, m3.surfaceOn.b, m3.statePressed)
            : root.hovered || root.visualFocus
                ? Qt.rgba(m3.surfaceOn.r, m3.surfaceOn.g, m3.surfaceOn.b, m3.stateHover)
                : 'transparent'
    }

    contentItem: RowLayout {
        id: layout
        spacing: m3.space16
        opacity: root.enabled ? 1 : m3.disabledContentOpacity

        M3Icon {
            visible: root.leadingIcon != ''
            Layout.alignment: Qt.AlignVCenter
            source: root.leadingIcon
            color: m3.surfaceVariantOn
        }

        ColumnLayout {
            Layout.fillWidth: true
            Layout.alignment: Qt.AlignVCenter
            spacing: 0

            M3Text {
                Layout.fillWidth: true
                role: 'bodyLarge'
                text: root._headline
                wrapMode: Text.Wrap
                lineHeightMode: Text.ProportionalHeight
                lineHeight: 1.0
            }
            M3Text {
                Layout.fillWidth: true
                visible: root.supporting !== ''
                role: 'bodyMedium'
                color: m3.surfaceVariantOn
                wrapMode: Text.Wrap
                lineHeightMode: Text.ProportionalHeight
                lineHeight: 1.0
                text: root.supporting
            }
        }

        // room for the indicator, which the style draws at the right edge
        Item {
            Layout.preferredWidth: root.indicator ? root.indicator.width + root.spacing : 0
            Layout.preferredHeight: 1
        }
    }
}
