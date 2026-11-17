import QtQuick
import QtQuick.Controls
import QtQuick.Controls.Material

// Material 3 chip (assist/filter): height 32, radius 8, 1 px outlineVariant border, leading icon 18.
// checkable chips fill with secondaryContainer when checked. tone: '' | 'error' | 'tertiary' fills
// the container of that role without a border (status chips such as "Disconnected", "Testnet").
AbstractButton {
    id: root

    property string tone: ''
    property url iconSource
    property color iconColor: tone === 'error' ? m3.errorContainerOn
        : tone === 'tertiary' ? m3.tertiaryContainerOn
        : m3.primary

    readonly property color _container: tone === 'error' ? m3.errorContainer
        : tone === 'tertiary' ? m3.tertiaryContainer
        : checked ? m3.secondaryContainer
        : 'transparent'
    readonly property color _content: tone === 'error' ? m3.errorContainerOn
        : tone === 'tertiary' ? m3.tertiaryContainerOn
        : checked ? m3.secondaryContainerOn
        : m3.surfaceVariantOn

    implicitHeight: 32
    implicitWidth: row.implicitWidth + leftPadding + rightPadding
    leftPadding: iconSource != '' ? 8 : 16
    rightPadding: 16
    opacity: enabled ? 1 : m3.disabledContentOpacity

    background: Rectangle {
        radius: m3.radiusS
        color: root.pressed
            ? m3.stateLayer(root._container.a > 0 ? root._container : m3.surface, root._content, m3.statePressed)
            : root._container
        border.width: root.tone === '' && !root.checked ? 1 : 0
        border.color: m3.outlineVariant
    }

    contentItem: Item {
        implicitWidth: row.implicitWidth
        implicitHeight: row.implicitHeight
        Row {
            id: row
            anchors.verticalCenter: parent.verticalCenter
            spacing: 8
            M3Icon {
                anchors.verticalCenter: parent.verticalCenter
                visible: root.iconSource != ''
                source: root.iconSource
                size: 18
                color: root.iconColor
            }
            M3Text {
                anchors.verticalCenter: parent.verticalCenter
                role: 'labelLarge'
                text: root.text
                color: root._content
            }
        }
    }
}
