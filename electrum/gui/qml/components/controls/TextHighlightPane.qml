import QtQuick
import QtQuick.Layouts
import QtQuick.Controls
import QtQuick.Controls.Material

Pane {
    padding: constants.paddingSmall

    property color backgroundColor: constants.highlightBackground
    property color borderColor: 'transparent'

    background: Rectangle {
        color: backgroundColor
        border.color: borderColor ? borderColor : backgroundColor
        radius: constants.paddingSmall
    }
}
