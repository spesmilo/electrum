import QtQuick 2.6
import QtQuick.Layouts 1.0
import QtQuick.Controls 2.1

Item {
    property alias auto_server: auto_server_cb.checked
    property alias address: address_tf.text

    ColumnLayout {
        width: parent.width

        Label {
            text: qsTr('Server settings')
        }

        CheckBox {
            id: auto_server_cb
            text: qsTr('Select server automatically')
            checked: true
        }

        GridLayout {
            columns: 2
            Layout.fillWidth: true

            Label {
                text: qsTr("Server")
                enabled: address_tf.enabled
            }

            TextField {
                id: address_tf
                enabled: !auto_server_cb.checked
            }
        }
    }
}
