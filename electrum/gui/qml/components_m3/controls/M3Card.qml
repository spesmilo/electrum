import QtQuick
import QtQuick.Controls
import QtQuick.Controls.Material

// Material 3 card: a tonal container (no shadow, elevation by tone). Children go inside, with padding.
// clickable: true adds a state layer and emits clicked().
Pane {
    id: root

    property color color: m3.surfaceContainerLow
    property color contentColor: m3.surfaceOn
    property int radius: m3.radiusL
    property bool clickable: false
    signal clicked()

    padding: m3.space16
    Material.elevation: 0

    background: Rectangle {
        color: root.color
        radius: root.radius

        Rectangle {
            anchors.fill: parent
            radius: parent.radius
            visible: root.clickable && tap.pressed
            color: Qt.rgba(root.contentColor.r, root.contentColor.g, root.contentColor.b, m3.statePressed)
        }

        TapHandler {
            id: tap
            enabled: root.clickable
            onTapped: root.clicked()
        }
    }
}
