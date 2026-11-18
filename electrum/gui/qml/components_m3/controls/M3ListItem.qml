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
    property int headlineMaxLines: 1  // > 1: a long headline wraps instead of being elided
    property Component leading
    property Component trailing
    property url leadingIcon       // shortcut for a 24 dp icon in onSurfaceVariant

    readonly property Item trailingItem: trailingLoader.item

    Layout.fillWidth: true
    // the supporting text wraps when it is wider than its column; measured with TextMetrics, not with
    // supportingText.lineCount (that one is updated inside the layout pass that reads implicitHeight: binding loop)
    readonly property bool _supportingWraps: supporting !== '' && supportingMetrics.advanceWidth > supportingText.width
    implicitHeight: Math.max(supporting === '' ? 56 : (_supportingWraps ? 88 : 72),
                             layout.implicitHeight + 2 * 8)
    leftPadding: m3.space16
    rightPadding: m3.space16 + (trailing ? -4 : 0)
    topPadding: 8
    bottomPadding: 8
    text: headline

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
                wrapMode: root.headlineMaxLines > 1 ? Text.Wrap : Text.NoWrap
                maximumLineCount: root.headlineMaxLines
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

    TextMetrics {
        id: supportingMetrics
        font: supportingText.font
        text: root.supporting
    }

    Component {
        id: leadingIconComponent
        M3Icon {
            source: root.leadingIcon
            color: m3.surfaceVariantOn
        }
    }
}
