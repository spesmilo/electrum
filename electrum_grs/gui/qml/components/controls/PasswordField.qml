import QtQuick 2.6
import QtQuick.Layouts 1.0
import QtQuick.Controls 2.1

RowLayout {
    id: root
    property alias text: password_tf.text
    property alias tf: password_tf
    signal accepted

    TextField {
        id: password_tf
        echoMode: TextInput.Password
        inputMethodHints: Qt.ImhSensitiveData
        Layout.fillWidth: true
        Layout.minimumWidth: fontMetrics.advanceWidth('X') * 16
        onAccepted: root.accepted()
    }
    ToolButton {
        icon.source: '../../../icons/eye1.png'
        onClicked: {
            password_tf.echoMode = password_tf.echoMode == TextInput.Password ? TextInput.Normal : TextInput.Password
        }
    }

    FontMetrics {
        id: fontMetrics
        font: password_tf.font
    }

}
