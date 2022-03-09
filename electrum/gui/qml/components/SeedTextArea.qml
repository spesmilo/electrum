import QtQuick 2.6
import QtQuick.Layouts 1.0
import QtQuick.Controls 2.1
import QtQuick.Controls.Material 2.0

TextArea {
    id: seedtext
    Layout.fillWidth: true
    Layout.minimumHeight: 80
    rightPadding: 16
    leftPadding: 16
    wrapMode: TextInput.WordWrap
    font.bold: true
    font.pixelSize: 18
    background: Rectangle {
        color: "transparent"
        border.color: Material.accentColor
    }
}
