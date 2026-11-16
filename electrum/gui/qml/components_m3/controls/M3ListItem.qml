import QtQuick
import QtQuick.Layouts
import QtQuick.Controls
import QtQuick.Controls.Material

// Material 3 list item: optional leading item (avatar 40 or icon 24), headline (bodyLarge),
// supporting text (bodyMedium, onSurfaceVariant, wraps), optional trailing item.
// Height 56 / 72 / 88 by the number of lines. Disabled rows show content at 0.38 opacity.
ItemDelegate {
    id: root

    property string headline
    property string supporting
    property int supportingMaxLines: 2
    property Component leading
    property Component trailing
    property url leadingIcon       // shortcut for a 24 dp icon in onSurfaceVariant

    readonly property Item trailingItem: trailingLoader.item

    Layout.fillWidth: true
    implicitHeight: Math.max(supporting === '' ? 56 : (supportingText.lineCount > 1 ? 88 : 72),
                             layout.implicitHeight + 2 * 8)
    leftPadding: m3.space16
    rightPadding: m3.space16 + (trailing ? -4 : 0)
    topPadding: 8
    bottomPadding: 8
    text: headline
    Accessible.name: headline
    Accessible.description: supporting

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

        Loader {
            Layout.alignment: Qt.AlignVCenter
            active: root.leading || root.leadingIcon != ''
            visible: active
            sourceComponent: root.leading ? root.leading : leadingIconComponent
        }

        ColumnLayout {
            Layout.fillWidth: true
            Layout.alignment: Qt.AlignVCenter
            spacing: 0

            M3Text {
                Layout.fillWidth: true
                role: 'bodyLarge'
                text: root.headline
                elide: Text.ElideRight
            }
            M3Text {
                id: supportingText
                Layout.fillWidth: true
                visible: root.supporting !== ''
                role: 'bodyMedium'
                color: m3.surfaceVariantOn
                wrapMode: Text.Wrap
                maximumLineCount: root.supportingMaxLines
                elide: Text.ElideRight
                lineHeightMode: Text.ProportionalHeight
                lineHeight: 1.0
                text: root.supporting
            }
        }

        Loader {
            id: trailingLoader
            Layout.alignment: Qt.AlignVCenter
            active: root.trailing
            visible: active
            sourceComponent: root.trailing
        }
    }

    Component {
        id: leadingIconComponent
        M3Icon {
            source: root.leadingIcon
            color: m3.surfaceVariantOn
        }
    }
}
