import QtQuick
import QtQuick.Layouts
import QtQuick.Controls
import QtQuick.Controls.Material

import org.electrum 1.0

import "controls"

ElDialog {
    id: rootItem

    title: qsTr('Server settings')
    iconSource: Qt.resolvedUrl('../../icons/network.png')

    width: parent.width
    height: parent.height

    padding: 0

    ColumnLayout {
        width: parent.width
        height: parent.height
        spacing: 0

        ColumnLayout {
            Layout.fillWidth: true
            Layout.fillHeight: true
            Layout.leftMargin: constants.paddingLarge
            Layout.rightMargin: constants.paddingLarge

            ServerConfig {
                id: serverconfig
                Layout.fillWidth: true
                Layout.fillHeight: true
            }
        }

        FlatButton {
            Layout.fillWidth: true
            text: qsTr('Ok')
            icon.source: '../../icons/confirmed.png'
            onClicked: {
                let auto_connect = serverconfig.serverConnectMode == ServerConnectModeComboBox.Mode.Autoconnect
                let server = serverconfig.address
                let one_server = serverconfig.serverConnectMode == ServerConnectModeComboBox.Mode.Single
                Network.setServerParameters(server, auto_connect, one_server)
                rootItem.close()
            }
        }
    }

}
