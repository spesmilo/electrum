import QtQuick
import QtQuick.Controls
import QtQuick.Controls.Material

// Material 3 segmented button (single select). model: [{ text, value }]
// currentValue is the selection shown; activated(value) is emitted on user selection only.
Rectangle {
    id: root

    property var model: []
    property var currentValue
    signal activated(var value)

    implicitHeight: 40
    implicitWidth: 320
    radius: height / 2
    color: 'transparent'
    border.width: 1
    border.color: m3.outline
    clip: true

    Row {
        anchors.fill: parent
        anchors.margins: 1

        Repeater {
            model: root.model

            delegate: AbstractButton {
                id: segment
                required property var modelData
                required property int index
                readonly property bool selected: modelData.value === root.currentValue

                width: parent.width / Math.max(1, root.model.length)
                height: parent.height
                text: modelData.text
                checkable: true
                checked: selected
                Accessible.role: Accessible.RadioButton
                Accessible.name: modelData.text

                onClicked: {
                    checked = Qt.binding(function() { return segment.selected })
                    if (!selected)
                        root.activated(modelData.value)
                }

                background: Item {
                    // selected fill; the outer segments follow the rounded outline
                    Rectangle {
                        anchors.fill: parent
                        color: segment.selected ? m3.secondaryContainer : 'transparent'
                        radius: segment.index === 0 || segment.index === root.model.length - 1
                            ? height / 2 : 0
                    }
                    Rectangle {
                        // square off the inner side of the rounded outer segments
                        visible: segment.selected && root.model.length > 1
                            && (segment.index === 0 || segment.index === root.model.length - 1)
                        width: parent.width / 2
                        height: parent.height
                        x: segment.index === 0 ? parent.width / 2 : 0
                        color: m3.secondaryContainer
                    }
                    Rectangle {
                        anchors.fill: parent
                        visible: segment.pressed
                        color: Qt.rgba(m3.surfaceOn.r, m3.surfaceOn.g, m3.surfaceOn.b, m3.statePressed)
                    }
                    Rectangle {
                        visible: segment.index > 0
                        width: 1
                        height: parent.height
                        color: m3.outline
                    }
                }

                contentItem: Item {
                    Row {
                        anchors.centerIn: parent
                        spacing: 8
                        M3Text {
                            visible: segment.selected
                            role: 'labelLarge'
                            text: '✓'
                            color: m3.secondaryContainerOn
                        }
                        M3Text {
                            role: 'labelLarge'
                            text: segment.modelData.text
                            elide: Text.ElideRight
                            color: segment.selected ? m3.secondaryContainerOn : m3.surfaceOn
                        }
                    }
                }
            }
        }
    }
}
