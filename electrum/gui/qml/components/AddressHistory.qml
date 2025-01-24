import QtQuick
import QtQuick.Layouts
import QtQuick.Controls
import QtQuick.Controls.Material

import org.electrum 1.0

import "controls"

Pane {
    id: root
    width: parent.width
    height: parent.height
    padding: 0

    required property string address

    ColumnLayout {
        anchors.fill: parent
        spacing: 10

        ColumnLayout {
            Layout.fillWidth: true
            Layout.margins: 10
            Label {
                text: qsTr('Transaction history for address:')
                color: Material.accentColor
                Layout.fillWidth: true
                wrapMode: Text.Wrap
            }

            TextHighlightPane {
                Layout.fillWidth: true
                Label {
                    text: address
                    width: parent.width
                    font.family: FixedFont
                    wrapMode: Text.Wrap
                }
            }
        }

        Frame {
            Layout.fillWidth: true
            Layout.fillHeight: true

            verticalPadding: bg.lineWidth
            horizontalPadding: 0
            background: PaneInsetBackground { id: bg; vertical: false }

            History {
                anchors.fill: parent
                forAddress: root.address
            }
        }
    }
}
