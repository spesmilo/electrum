import QtQuick 2.6
import QtQuick.Layouts 1.0
import QtQuick.Controls 2.0

Item {
    id: rootItem

    property string title: 'History'

    Column {
        width: parent.width

        ListView {
            width: parent.width
            height: 200

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
                    columns: 4

                    x: 6
                    width: delegate.width - 12

                    Item {
                        id: indicator
                        Layout.fillHeight: true
                        Layout.rowSpan: 2
                        Rectangle {
                            width: 3
                            color: model.incoming ? 'green' : 'red'
                            y: 2
                            height: parent.height - 4
                        }
                    }

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

                        sourceSize.width: 32
                        sourceSize.height: 32
                        Layout.alignment: Qt.AlignVCenter
                        source: tx_icons[Math.min(6,model.confirmations)]
                    }

                    Column {
                        Layout.fillWidth: true

                        Label {
                            text: model.label !== '' ? model.label : '<no label>'
                            color: model.label !== '' ? 'black' : 'gray'
                            font.bold: model.label !== '' ? true : false
                        }
                        Label {
                            font.pointSize: 7
                            text: model.date
                        }
                    }

                    Column {
                        id: valuefee
                        Label {
                            text: model.bc_value
                            font.bold: true
                        }
                        Label {
                            font.pointSize: 6
                            text: 'fee: ' + (model.fee !== undefined ? model.fee : '0')
                        }
                    }

                    GridLayout {
                        id: extinfo
                        visible: false
                        columns: 2
                        Layout.columnSpan: 3

                        Label { text: 'txid' }
                        Label {
                            font.pointSize: 6
                            text: model.txid
                            elide: Text.ElideMiddle
                            Layout.fillWidth: true
                        }
                        Label { text: 'height' }
                        Label {
                            font.pointSize: 7
                            text: model.height
                        }
                        Label { text: 'confirmations' }
                        Label {
                            font.pointSize: 7
                            text: model.confirmations
                        }
                        Label { text: 'address' }
                        Label {
                            font.pointSize: 7
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
            } // delegate
        }

    }

}
