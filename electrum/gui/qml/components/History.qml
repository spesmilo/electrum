import QtQuick 2.6
import QtQuick.Layouts 1.0
import QtQuick.Controls 2.0
import QtQuick.Controls.Material 2.0

import org.electrum 1.0

Pane {
    id: rootItem
    visible: Daemon.currentWallet !== undefined
    clip: true

    ListView {
        id: listview
        width: parent.width
        height: parent.height

        model: Daemon.currentWallet.historyModel

        delegate: Item {
            id: delegate
            width: ListView.view.width
            height: txinfo.height

            MouseArea {
                anchors.fill: delegate
                onClicked: extinfo.visible = !extinfo.visible
            }

            GridLayout {
                id: txinfo
                columns: 3

                x: 6
                width: delegate.width - 12

                Image {
                    readonly property variant tx_icons : [
                        "../../../gui/icons/unconfirmed.png",
                        "../../../gui/icons/clock1.png",
                        "../../../gui/icons/clock2.png",
                        "../../../gui/icons/clock3.png",
                        "../../../gui/icons/clock4.png",
                        "../../../gui/icons/clock5.png",
                        "../../../gui/icons/confirmed.png"
                    ]

                    Layout.preferredWidth: 32
                    Layout.preferredHeight: 32
                    Layout.alignment: Qt.AlignVCenter
                    Layout.rowSpan: 2
                    source: tx_icons[Math.min(6,model.confirmations)]
                }

                Label {
                    font.pixelSize: 18
                    Layout.fillWidth: true
                    text: model.label !== '' ? model.label : '<no label>'
                    color: model.label !== '' ? Material.accentColor : 'gray'
                }
                Label {
                    id: valueLabel
                    font.family: FixedFont
                    font.pixelSize: 15
                    text: Config.formatSats(model.bc_value)
                    font.bold: true
                    color: model.incoming ? "#ff80ff80" : "#ffff8080"
                }
                Label {
                    font.pixelSize: 12
                    text: model.date
                }
                Label {
                    font.pixelSize: 10
                    text: 'fee: ' + (model.fee !== undefined ? model.fee : '0')
                }

                GridLayout {
                    id: extinfo
                    visible: false
                    columns: 2
                    Layout.columnSpan: 3

                    Label { text: 'txid' }
                    Label {
                        font.pixelSize: 10
                        text: model.txid
                        elide: Text.ElideMiddle
                        Layout.fillWidth: true
                    }
                    Label { text: 'height' }
                    Label {
                        font.pixelSize: 10
                        text: model.height
                    }
                    Label { text: 'confirmations' }
                    Label {
                        font.pixelSize: 10
                        text: model.confirmations
                    }
                    Label { text: 'address' }
                    Label {
                        font.pixelSize: 10
                        elide: Text.ElideMiddle
                        Layout.fillWidth: true
                        text: {
                            for (var i=0; i < Object.keys(model.outputs).length; i++) {
                                if (model.outputs[i].value === model.bc_value) {
                                    return model.outputs[i].address
                                }
                            }
                        }
                    }
                }

            }

            // as the items in the model are not bindings to QObjects,
            // hook up events that might change the appearance
            Connections {
                target: Config
                function onBaseUnitChanged() {
                    valueLabel.text = Config.formatSats(model.bc_value)
                }
                function onThousandsSeparatorChanged() {
                    valueLabel.text = Config.formatSats(model.bc_value)
                }
            }

        } // delegate

        ScrollIndicator.vertical: ScrollIndicator { }

    }

}
