import QtQuick
import QtQuick.Controls
import QtQuick.Controls.impl
import QtQuick.Controls.Material
import QtQuick.Controls.Material.impl

Rectangle {
    id: root

    property Item delegate

    implicitHeight: delegate.Material.delegateHeight

    color: delegate.highlighted ? delegate.Material.listHighlightColor : "transparent"

    Ripple {
        width: parent.width
        height: parent.height

        clip: visible
        pressed: delegate.pressed
        anchor: delegate
        active: enabled && (delegate.down || delegate.visualFocus || delegate.hovered)
        color: delegate.Material.rippleColor
    }
}
