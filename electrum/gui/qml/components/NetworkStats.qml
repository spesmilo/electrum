import QtQuick 2.6
import QtQuick.Layouts 1.0
import QtQuick.Controls 2.0
import QtQuick.Controls.Material 2.0

import "controls"

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

        NetworkStatusIndicator {}

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
