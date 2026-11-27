import QtQuick
import QtQuick.Controls
import QtQuick.Controls.Material

// Material 3 card: a tonal container (no shadow, elevation by tone). Children go inside, with padding.
// clickable: true adds a state layer and emits clicked() on a tap anywhere on the card, padding included.
Pane {
    id: root

    property color color: m3.surfaceContainerLow
    property color contentColor: m3.surfaceOn
    property int radius: m3.radiusL
    property bool clickable: false
    signal clicked()

    padding: m3.space16
    Material.elevation: 0

    // The handler belongs to the Pane itself (its `data`): a handler declared in the body would go to the
    // content item (the default property contentData), which excludes the padding, and one inside
    // `background` never sees the press (the background lies under the Pane, which accepts all buttons).
    // longPressThreshold 0: a long hold still taps, as the MouseArea of the classic BalanceSummary.
    data: [
        TapHandler {
            id: tap
            enabled: root.clickable
            longPressThreshold: 0
            onTapped: root.clicked()
        }
    ]

    // No accessibility attached properties: Electrum's Android Qt lacks them, and all of M3 would fail to load.

    background: Rectangle {
        color: root.color
        radius: root.radius

        Rectangle {
            anchors.fill: parent
            radius: parent.radius
            visible: root.clickable && tap.pressed
            color: Qt.rgba(root.contentColor.r, root.contentColor.g, root.contentColor.b, m3.statePressed)
        }
    }
}
