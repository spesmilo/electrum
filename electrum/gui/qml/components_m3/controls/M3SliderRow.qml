import QtQuick
import QtQuick.Layouts
import QtQuick.Controls
import QtQuick.Controls.Material

// List row with a slider under the headline and the value text on the right.
// `value` is meant to be bound; moved(value) is emitted on user action only.
Pane {
    id: root

    property string headline
    property string supporting
    property string valueText
    property alias from: slider.from
    property alias to: slider.to
    property alias stepSize: slider.stepSize
    property alias snapMode: slider.snapMode
    property real value: 0
    signal moved(real value)

    Layout.fillWidth: true
    leftPadding: m3.space16
    rightPadding: m3.space16
    topPadding: m3.space12
    bottomPadding: m3.space4
    opacity: enabled ? 1 : m3.disabledContentOpacity
    background: Item {}

    contentItem: ColumnLayout {
        spacing: 0
        RowLayout {
            Layout.fillWidth: true
            M3Text {
                Layout.fillWidth: true
                role: 'bodyLarge'
                text: root.headline
                elide: Text.ElideRight
            }
            M3Text {
                role: 'labelLarge'
                color: m3.primary
                text: root.valueText
            }
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
        Slider {
            id: slider
            Layout.fillWidth: true
            value: root.value
            Accessible.name: root.headline
            onMoved: {
                var v = slider.value
                root.moved(v)
                slider.value = Qt.binding(function() { return root.value })
            }
        }
    }
}
