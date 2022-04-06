import QtQuick 2.6
import QtQuick.Layouts 1.0
import QtQuick.Controls 2.1
import QtQuick.Controls.Material 2.0

TextArea {
    id: seedtext
    Layout.fillWidth: true
    Layout.minimumHeight: 80
    rightPadding: constants.paddingLarge
    leftPadding: constants.paddingLarge
    wrapMode: TextInput.WordWrap
    font.bold: true
    font.pixelSize: constants.fontSizeLarge
    inputMethodHints: Qt.ImhSensitiveData | Qt.ImhPreferLowercase | Qt.ImhNoPredictiveText
    background: Rectangle {
        color: "transparent"
        border.color: Material.accentColor
    }
}
