import QtQuick
import QtQuick.Layouts
import QtQuick.Controls
import QtQuick.Controls.Material

Pane {
    id: root

    property string key
    property int keycode: -1

    property QtObject kbd
    padding: 1

    function emitKeyEvent() {
        if (keycode == -1) {
            keycode = parseInt(key, 36) - 9 + 0x40 // map a-z char to key code
        }
        kbd.keyEvent(keycode, key)
    }

    FlatButton {
        anchors.fill: parent

        focusPolicy: Qt.NoFocus
        autoRepeat: true
        autoRepeatDelay: 750

        padding: 0

        onClicked: {
            emitKeyEvent()
        }

        // send keyevent again, otherwise it is ignored
        onDoubleClicked: {
            emitKeyEvent()
        }

        Label {
            anchors.centerIn: parent
            text: key
            font.pixelSize: Math.max(root.height * 0.67, constants.fontSizeSmall)
            verticalAlignment: Text.AlignVCenter
        }
    }
}
