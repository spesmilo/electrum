import QtQuick 2.6
import QtQuick.Layouts 1.0
import QtQuick.Controls 2.14
import QtQuick.Controls.Material 2.0

import org.electrum 1.0

import "controls"

ElDialog {
    id: rootItem

    title: qsTr('Server settings')

    parent: Overlay.overlay
    modal: true
    standardButtons: Dialog.Close

    width: parent.width
    height: parent.height

    Overlay.modal: Rectangle {
        color: "#aa000000"
    }

    ColumnLayout {
        id: layout
        width: parent.width

        ServerConfig {
            id: serverconfig
        }

        RowLayout {
            Layout.alignment: Qt.AlignHCenter
            Button {
                text: qsTr('Ok')
                onClicked: {
                    Config.autoConnect = serverconfig.auto_server
                    if (!serverconfig.auto_server) {
                        Network.server = serverconfig.address
                    }
                    rootItem.close()
                }
            }
        }
    }

    Component.onCompleted: {
        serverconfig.auto_server = Config.autoConnect
        serverconfig.address = Network.server
    }
}
