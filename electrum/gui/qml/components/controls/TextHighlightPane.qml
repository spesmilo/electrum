import QtQuick
import QtQuick.Layouts
import QtQuick.Controls
import QtQuick.Controls.Material

Pane {
    padding: constants.paddingSmall

    property color backgroundColor: Qt.lighter(Material.background, 1.15)
    property color borderColor: 'transparent'

    background: Rectangle {
        color: backgroundColor
        border.color: borderColor ? borderColor : backgroundColor
        radius: constants.paddingSmall
    }
}
