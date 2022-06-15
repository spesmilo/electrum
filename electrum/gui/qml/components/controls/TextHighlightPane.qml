import QtQuick 2.6
import QtQuick.Layouts 1.0
import QtQuick.Controls 2.0
import QtQuick.Controls.Material 2.0

Pane {
    topPadding: constants.paddingSmall
    bottomPadding: constants.paddingSmall
    background: Rectangle {
        color: Qt.lighter(Material.background, 1.15)
        radius: constants.paddingSmall
    }
}
