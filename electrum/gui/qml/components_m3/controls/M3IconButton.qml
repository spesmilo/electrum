import QtQuick
import QtQuick.Controls
import QtQuick.Controls.Material

// 48x48 touch target with a 24 dp tinted icon and a tooltip naming the action
ToolButton {
    id: root

    property string tooltip

    implicitWidth: 48
    implicitHeight: 48
    padding: 12
    display: AbstractButton.IconOnly
    icon.width: 24
    icon.height: 24
    icon.color: m3.surfaceVariantOn

    ToolTip.visible: tooltip !== '' && hovered
    ToolTip.delay: 800
    ToolTip.text: tooltip
    Accessible.name: tooltip
}
