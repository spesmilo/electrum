import QtQuick
import QtQuick.Controls
import QtQuick.Controls.Material

// 48x48 touch target with a 24 dp tinted icon and a tooltip naming the action.
// Own background: the Material 3 state layer, a 40 dp circle in the color of the icon (hover, focus, pressed),
// as M3Button. The Ripple of the Material ToolButton drew its hover circle in the corner of the window (0,0)
// under the software renderer of Qt Quick, instead of around the button.
// The tooltip is an own ToolTip of the button (Material 3 plain tooltip: inverseSurface, bodySmall), shown while
// the button is hovered, the same condition as the attached ToolTip before (whether a long press on a phone
// shows it is not checked yet). The attached ToolTip shared by the window was drawn with the dark window theme;
// the own one binds root.tooltip directly, so a text changed by a click (the eye of M3PasswordField) shows at once.
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

    background: Item {
        implicitWidth: 48
        implicitHeight: 48
        Rectangle {
            anchors.centerIn: parent
            width: 40
            height: 40
            radius: 20
            readonly property real _alpha: !root.enabled ? 0
                : root.down ? m3.statePressed : root.visualFocus ? m3.stateFocus : root.hovered ? m3.stateHover : 0
            color: Qt.rgba(root.icon.color.r, root.icon.color.g, root.icon.color.b, _alpha)
        }
    }

    ToolTip {
        id: tip
        visible: root.tooltip !== '' && root.hovered
        delay: 800
        text: root.tooltip
        // below the button, centered on it (inside the window: the popup is kept within its parent window)
        x: (root.width - width) / 2
        y: root.height + 4
        padding: 0
        leftPadding: 8
        rightPadding: 8
        topPadding: 4
        bottomPadding: 4
        contentItem: M3Text {
            role: 'bodySmall'
            color: m3.inverseSurfaceOn
            text: tip.text
        }
        background: Rectangle {
            implicitHeight: 24
            radius: 4
            color: m3.inverseSurface
        }
    }
}
