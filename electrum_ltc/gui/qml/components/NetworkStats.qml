import QtQuick 2.6
import QtQuick.Layouts 1.0
import QtQuick.Controls 2.0
import QtQuick.Controls.Material 2.0

import "controls"

Pane {
    property string title: qsTr('Network')

    GridLayout {
        columns: 2

        Label {
            text: qsTr("Network: ");
            color: Material.primaryHighlightedTextColor;
            font.bold: true
        }
        Label {
            text: Network.networkName
        }

        Label {
            text: qsTr("Server: ");
            color: Material.primaryHighlightedTextColor;
            font.bold: true
        }
        Label {
            text: Network.server
        }

        Label {
            text: qsTr("Local Height: ");
            color: Material.primaryHighlightedTextColor;
            font.bold: true

        }
        Label {
            text: Network.height
        }

        Label {
            text: qsTr("Status: ");
            color: Material.primaryHighlightedTextColor;
            font.bold: true
        }

        RowLayout {
            NetworkStatusIndicator {}

            Label {
                text: Network.status
            }
        }

        Label {
            text: qsTr("Network fees: ");
            color: Material.primaryHighlightedTextColor;
            font.bold: true
        }
        Label {
            id: feeHistogram
        }

        Label {
            text: qsTr("Gossip: ");
            color: Material.primaryHighlightedTextColor;
            font.bold: true
        }
        ColumnLayout {
            visible: Config.useGossip
            Label {
                text: qsTr('%1 peers').arg(Network.gossipInfo.peers)
            }
            Label {
                text: qsTr('%1 channels to fetch').arg(Network.gossipInfo.unknown_channels)
            }
            Label {
                text: qsTr('%1 nodes, %2 channels').arg(Network.gossipInfo.db_nodes).arg(Network.gossipInfo.db_channels)
            }
        }
        Label {
            text: qsTr("disabled");
            visible: !Config.useGossip
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
