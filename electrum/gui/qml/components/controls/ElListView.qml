import QtQuick
import QtQuick.Layouts
import QtQuick.Controls
import QtQuick.Controls.Material

ListView {
    id: root

    // avoid interference with android back-gesture by defining deadzones
    // you can override to 0 if listview is away from left or right edge.
    property int exclusionZone: constants.fingerWidth / 2
    property int leftExclusionZone: exclusionZone
    property int rightExclusionZone: exclusionZone

    MouseArea {
        anchors {top: root.top; left: root.left; bottom: root.bottom }
        visible: leftExclusionZone > 0
        width: leftExclusionZone
    }

    MouseArea {
        anchors { top: root.top; right: root.right; bottom: root.bottom }
        visible: rightExclusionZone > 0
        width: rightExclusionZone
    }

}
