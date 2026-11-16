import QtQuick
import QtQuick.Controls
import QtQuick.Controls.Material
import QtQuick.Controls.impl

// Material 3 button. variant: 'filled' | 'tonal' | 'outlined' | 'text'; size: 40 or 56; shape: 'full' | 'large'.
// Own background with a state layer (Material.background on a Button is not drawn reliably in
// Qt 6.10, and the Material ripple lives in the private Material.impl module).
Button {
    id: root

    property string variant: 'filled'
    property int size: 40
    property string shape: 'full'

    readonly property color containerColor: variant === 'filled'
        ? m3.primary
        : variant === 'tonal'
            ? m3.secondaryContainer
            : 'transparent'  // outlined, text
    readonly property color contentColor: variant === 'filled'
        ? m3.primaryOn
        : variant === 'tonal'
            ? m3.secondaryContainerOn
            : m3.primary

    flat: variant === 'text' || variant === 'outlined'
    topInset: size === 56 ? 0 : 4
    bottomInset: size === 56 ? 0 : 4
    leftPadding: variant === 'text' ? 12 : 24
    rightPadding: variant === 'text' ? 12 : 24
    implicitHeight: size + topInset + bottomInset
    font.pixelSize: m3.textStyle('labelLarge').size
    font.weight: m3.textStyle('labelLarge').weight
    font.letterSpacing: m3.textStyle('labelLarge').tracking
    font.capitalization: Font.MixedCase

    readonly property color _fg: enabled
        ? contentColor
        : Qt.rgba(m3.surfaceOn.r, m3.surfaceOn.g, m3.surfaceOn.b, m3.disabledContentOpacity)
    icon.color: _fg
    icon.width: 18
    icon.height: 18

    contentItem: IconLabel {
        spacing: 8
        mirrored: root.mirrored
        display: root.display
        icon: root.icon
        text: root.text
        font: root.font
        color: root._fg
    }

    // container with the state layer of the given opacity (transparent containers: the layer only)
    function _layered(opacity) {
        if (containerColor.a === 0)
            return Qt.rgba(contentColor.r, contentColor.g, contentColor.b, opacity)
        return opacity > 0 ? m3.stateLayer(containerColor, contentColor, opacity) : containerColor
    }

    background: Rectangle {
        implicitWidth: 64
        implicitHeight: root.size
        radius: root.shape === 'large' ? m3.radiusL : height / 2
        color: !root.enabled
            ? (root.containerColor.a === 0
                ? 'transparent'
                : Qt.rgba(m3.surfaceOn.r, m3.surfaceOn.g, m3.surfaceOn.b, m3.disabledContainerOpacity))
            : root._layered(root.down ? m3.statePressed : root.hovered || root.visualFocus ? m3.stateHover : 0)
        border.width: root.variant === 'outlined' ? 1 : 0
        border.color: root.enabled
            ? m3.outline
            : Qt.rgba(m3.surfaceOn.r, m3.surfaceOn.g, m3.surfaceOn.b, m3.disabledContainerOpacity)
    }
}
