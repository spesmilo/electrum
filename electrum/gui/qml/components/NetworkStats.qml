import QtQuick 2.6
import QtQuick.Layouts 1.0
import QtQuick.Controls 2.0
import QtQuick.Controls.Material 2.0

Pane {
    property string title: qsTr('Network')

    GridLayout {
        columns: 2

        Label { text: qsTr("Network: "); color: Material.primaryHighlightedTextColor; font.bold: true }
        Label { text: Network.networkName }
        Label { text: qsTr("Server: "); color: Material.primaryHighlightedTextColor; font.bold: true }
        Label { text: Network.server }
        Label { text: qsTr("Local Height: "); color: Material.primaryHighlightedTextColor; font.bold: true }
        Label { text: Network.height }
        Label { text: qsTr("Status: "); color: Material.primaryHighlightedTextColor; font.bold: true }
        Label { text: Network.status }
        Label { text: qsTr("Wallet: "); color: Material.primaryHighlightedTextColor; font.bold: true }
        Label { text: Daemon.walletName }
    }
}
