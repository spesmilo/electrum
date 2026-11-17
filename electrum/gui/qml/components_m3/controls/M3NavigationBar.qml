import QtQuick
import QtQuick.Layouts
import QtQuick.Controls
import QtQuick.Controls.Material

// Material 3 navigation bar. model: [{ icon: url, text: string }]; bind currentIndex, handle activated(index)
// The Android navigation bar strip below is drawn by main.qml (navigationBarBackgroundColor of the page).
Rectangle {
    id: root

    property var model: []
    property int currentIndex: 0
    signal activated(int index)

    implicitHeight: m3.navigationBarHeight
    color: m3.surfaceContainer

    Material.theme: m3.dark ? Material.Dark : Material.Light
    Material.accent: m3.primary
    Material.foreground: m3.surfaceOn

    Row {
        anchors.fill: parent

        Repeater {
            model: root.model

            delegate: AbstractButton {
                id: item
                required property var modelData
                required property int index
                readonly property bool selected: index === root.currentIndex

                width: root.width / Math.max(1, root.model.length)
                height: root.height
                text: modelData.text

                // currentIndex is owned by the page (bound there); only report the choice
                onClicked: root.activated(index)

                contentItem: Item {
                    Column {
                        anchors.centerIn: parent
                        spacing: 4

                        Rectangle {
                            id: pill
                            anchors.horizontalCenter: parent.horizontalCenter
                            width: 64
                            height: 32
                            radius: 16
                            color: item.selected
                                ? (item.pressed
                                    ? m3.stateLayer(m3.secondaryContainer, m3.secondaryContainerOn, m3.statePressed)
                                    : m3.secondaryContainer)
                                : (item.pressed
                                    ? Qt.rgba(m3.surfaceOn.r, m3.surfaceOn.g, m3.surfaceOn.b, m3.statePressed)
                                    : 'transparent')

                            M3Icon {
                                anchors.centerIn: parent
                                source: item.modelData.icon
                                color: item.selected ? m3.secondaryContainerOn : m3.surfaceVariantOn
                            }
                        }

                        M3Text {
                            anchors.horizontalCenter: parent.horizontalCenter
                            role: 'labelMedium'
                            text: item.modelData.text
                            font.weight: item.selected ? Font.Bold : Font.Medium
                            color: item.selected ? m3.surfaceOn : m3.surfaceVariantOn
                        }
                    }
                }
                background: Item {}
            }
        }
    }
}
