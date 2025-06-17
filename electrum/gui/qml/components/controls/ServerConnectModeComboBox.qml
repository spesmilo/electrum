import QtQuick
import QtQuick.Controls

import org.electrum 1.0

ElComboBox {
    id: control

    enum Mode {
        Autoconnect,
        Manual,
        Single
    }

    textRole: 'text'
    valueRole: 'value'

    model: [
        { text: qsTr('Auto-connect'), value: ServerConnectModeComboBox.Mode.Autoconnect },
        { text: qsTr('Manual server selection'), value: ServerConnectModeComboBox.Mode.Manual },
        { text: qsTr('Connect only to a single server'), value: ServerConnectModeComboBox.Mode.Single }
    ]

    Component.onCompleted: {
        if (!Network.autoConnectDefined) { // initial setup
            server_connect_mode_cb.currentIndex = server_connect_mode_cb.indexOfValue(
                ServerConnectModeComboBox.Mode.Manual)
        } else {
            server_connect_mode_cb.currentIndex = server_connect_mode_cb.indexOfValue(
                Network.autoConnect
                    ? ServerConnectModeComboBox.Mode.Autoconnect
                    : Network.oneServer
                        ? ServerConnectModeComboBox.Mode.Single
                        : ServerConnectModeComboBox.Mode.Manual
                )
        }
    }
}
