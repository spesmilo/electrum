import QtQuick
import QtQuick.Layouts

// Group of list rows on surfaceContainerLow, radius 16; 1 px dividers (surfaceContainerHighest,
// inset 16) between visible rows. Rows are the children (M3ListItem and the like).
Rectangle {
    id: root

    default property alias rows: column.data

    color: m3.surfaceContainerLow
    radius: m3.radiusL
    implicitHeight: column.implicitHeight
    implicitWidth: column.implicitWidth
    clip: true

    ColumnLayout {
        id: column
        width: parent.width
        spacing: 0
    }

    Repeater {
        // a divider above every visible row but the first visible one
        model: column.children.length
        delegate: Rectangle {
            required property int index
            readonly property Item row: column.children[index]
            readonly property bool firstVisible: {
                for (var i = 0; i < index; i++)
                    if (column.children[i].visible)
                        return false
                return true
            }
            visible: row && row.visible && !firstVisible
            x: m3.space16
            y: row ? row.y : 0
            width: root.width - 2 * m3.space16
            height: 1
            color: m3.surfaceContainerHighest
        }
    }
}
