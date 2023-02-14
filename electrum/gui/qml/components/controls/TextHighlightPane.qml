import QtQuick 2.6
import QtQuick.Layouts 1.0
import QtQuick.Controls 2.0
import QtQuick.Controls.Material 2.0

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
