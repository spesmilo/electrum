import QtQuick 2.6
import QtQuick.Layouts 1.0
import QtQuick.Controls 2.0
import QtQuick.Controls.Material 2.0

Pane {
    property string title: qsTr('Network')

    GridLayout {
        columns: 3

        Label {
            text: qsTr("Network: ");
            color: Material.primaryHighlightedTextColor;
            font.bold: true
        }
        Label {
            text: Network.networkName
            Layout.columnSpan: 2
        }

        Label {
            text: qsTr("Server: ");
            color: Material.primaryHighlightedTextColor;
            font.bold: true
        }
        Label {
            text: Network.server
            Layout.columnSpan: 2
        }

        Label {
            text: qsTr("Local Height: ");
            color: Material.primaryHighlightedTextColor;
            font.bold: true

        }
        Label {
            text: Network.height
            Layout.columnSpan: 2
        }

        Label {
            text: qsTr("Status: ");
            color: Material.primaryHighlightedTextColor;
            font.bold: true
        }
        Image {
            Layout.preferredWidth: constants.iconSizeSmall
            Layout.preferredHeight: constants.iconSizeSmall
            source: Network.status == 'connecting' || Network.status == 'disconnected'
                ? '../../icons/status_disconnected.png' :
                    Daemon.currentWallet.isUptodate
                    ? '../../icons/status_connected.png'
                    : '../../icons/status_lagging.png'
        }
        Label {
            text: Network.status
        }

        Label {
            text: qsTr("Network fees: ");
            color: Material.primaryHighlightedTextColor;
            font.bold: true
        }
        Label {
            id: feeHistogram
            Layout.columnSpan: 2
        }
    }

    function setFeeHistogram() {
        var txt = ''
        Network.feeHistogram.forEach(function(item) {
            txt = txt + item[0] + ': ' + item[1] + '\n';
        })
        feeHistogram.text = txt.trim()
    }

    Connections {
        target: Network
        function onFeeHistogramUpdated() {
            setFeeHistogram()
        }
    }

    Component.onCompleted: setFeeHistogram()
}
