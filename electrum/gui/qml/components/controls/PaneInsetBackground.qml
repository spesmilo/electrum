import QtQuick
import QtQuick.Controls.Material

Rectangle {
    property color baseColor: Material.background
    property bool vertical: true
    property bool horizontal: true
    property int lineWidth: 2

    Rectangle {
        anchors { left: parent.left; top: parent.top; right: parent.right }
        height: lineWidth
        color: Qt.darker(baseColor, 1.50)
        visible: horizontal
    }
    Rectangle {
        anchors { left: parent.left; top: parent.top; bottom: parent.bottom }
        width: lineWidth
        color: Qt.darker(baseColor, 1.50)
        visible: vertical
    }
    Rectangle {
        anchors { left: parent.left; bottom: parent.bottom; right: parent.right }
        height: lineWidth
        color: Qt.lighter(baseColor, 1.50)
        visible: horizontal
    }
    Rectangle {
        anchors { right: parent.right; top: parent.top; bottom: parent.bottom }
        width: lineWidth
        color: Qt.lighter(baseColor, 1.50)
        visible: vertical
    }
    color: Qt.darker(baseColor, 1.15)
}
