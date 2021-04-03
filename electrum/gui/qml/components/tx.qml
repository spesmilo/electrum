import QtQuick 2.6

Item {
    id: rootItem

    Column {
        width: parent.width

        EHeader {
            text: "History"
            width: parent.width
        }

        ListView {
            width: parent.width
            height: 200

            model: Daemon.currentWallet.historyModel
            delegate: Item {
                id: delegate
                width: parent.width
                height: txinfo.height

                MouseArea {
                    anchors.fill: delegate
                    onClicked: extinfo.visible = !extinfo.visible
                }

                Row {
                    id: txinfo
                    Rectangle {
                        width: 4
                        height: parent.height
                        color: model.incoming ? 'green' : 'red'
                    }

                    Column {

                        Row {
                            id: baseinfo
                            spacing: 10


                            Image {
                                readonly property variant tx_icons : [
                                    "../../icons/unconfirmed.png",
                                    "../../icons/clock1.png",
                                    "../../icons/clock2.png",
                                    "../../icons/clock3.png",
                                    "../../icons/clock4.png",
                                    "../../icons/clock5.png",
                                    "../../icons/confirmed.png"
                                ]

                                width: 32
                                height: 32
                                anchors.verticalCenter: parent.verticalCenter
                                source: tx_icons[Math.min(6,Math.floor(model.confirmations/20))]
                            }

                            Column {
                                id: content
                                width: delegate.width - x - valuefee.width

                                Text {
                                    text: model.label !== '' ? model.label : '<no label>'
                                    color: model.label !== '' ? 'black' : 'gray'
                                }
                                Text {
                                    font.pointSize: 7
                                    text: model.date
                                }
                            }

                            Column {
                                id: valuefee
                                width: delegate.width * 0.25
                                Text {
                                    text: model.bc_value
                                }
                                Text {
                                    font.pointSize: 7
                                    text: 'fee: ' + (model.fee !== undefined ? model.fee : '0')
                                }
                            }
                        }

                        Row {
                            id: extinfo
                            visible: false

                            Column {
                                id: extinfoinner
                                Text {
                                    font.pointSize: 6
                                    text: 'txid: ' + model.txid
                                }
                                Text {
                                    font.pointSize: 7
                                    text: 'height: ' + model.height
                                }
                                Text {
                                    font.pointSize: 7
                                    text: 'confirmations: ' + model.confirmations
                                }
                                Text {
                                    font.pointSize: 7
                                    text: {
                                        for (var i=0; i < Object.keys(model.outputs).length; i++) {
                                            if (model.outputs[i].value === model.bc_value) {
                                                return 'address: ' + model.outputs[i].address
                                            }
                                        }
                                    }
                                }
                            }
                        }


                    }
                }
            } // delegate
        }

        EButton {
            text: 'Back'
            onClicked: app.stack.pop()
        }
    }

}
