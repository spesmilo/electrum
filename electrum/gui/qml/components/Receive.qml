import QtQuick 2.6
import QtQuick.Layouts 1.0
import QtQuick.Controls 2.0
import QtQuick.Controls.Material 2.0

import org.electrum 1.0

Pane {
    id: rootItem
    visible: Daemon.currentWallet !== undefined

    GridLayout {
        id: form
        width: parent.width
        rowSpacing: 10
        columnSpacing: 10
        columns: 3

        Label {
            text: qsTr('Message')
        }

        TextField {
            id: message
            onTextChanged: img.source = 'image://qrgen/' + text
            Layout.columnSpan: 2
            Layout.fillWidth: true
        }

        Label {
            text: qsTr('Requested Amount')
            wrapMode: Text.WordWrap
            Layout.preferredWidth: 50 // trigger wordwrap
        }

        TextField {
            id: amount
        }

        Item {
            Layout.rowSpan: 3
            width: img.width
            height: img.height

            Image {
                id: img
                cache: false
                anchors {
                    top: parent.top
                    left: parent.left
                }
                source: 'image://qrgen/test'
            }
        }

        Label {
            text: qsTr('Expires after')
            Layout.fillWidth: false
        }

        ComboBox {
            id: expires
            textRole: 'text'
            valueRole: 'value'
            model: ListModel {
                id: expiresmodel
                Component.onCompleted: {
                    // we need to fill the model like this, as ListElement can't evaluate script
                    expiresmodel.append({'text': qsTr('Never'), 'value': 0})
                    expiresmodel.append({'text': qsTr('10 minutes'), 'value': 10*60})
                    expiresmodel.append({'text': qsTr('1 hour'), 'value': 60*60})
                    expiresmodel.append({'text': qsTr('1 day'), 'value': 24*60*60})
                    expiresmodel.append({'text': qsTr('1 week'), 'value': 7*24*60*60})
                    expires.currentIndex = 0
                }
            }
        }

        Button {
            Layout.columnSpan: 2
            text: qsTr('Create Request')
            onClicked: {
                createRequest()
            }
        }
    }

    Frame {
        verticalPadding: 0
        horizontalPadding: 0

        anchors {
            top: form.bottom
            topMargin: constants.paddingXLarge
            left: parent.left
            right: parent.right
            bottom: parent.bottom
        }

        background: Rectangle {
            color: Qt.darker(Material.background, 1.25)
        }

        ColumnLayout {
            spacing: 0
            anchors.fill: parent

            Item {
                Layout.preferredHeight: hitem.height
                Layout.preferredWidth: parent.width
                Rectangle {
                    anchors.fill: parent
                    color: Qt.lighter(Material.background, 1.25)
                }
                RowLayout {
                    id: hitem
                    width: parent.width
                    Label {
                        text: qsTr('Receive queue')
                        font.pixelSize: constants.fontSizeXLarge
                    }
                }
            }

            ListView {
                Layout.fillHeight: true
                Layout.fillWidth: true
                clip: true

                model: Daemon.currentWallet.requestModel

                delegate: ItemDelegate {
                    id: root
                    height: item.height
                    width: ListView.view.width

                    onClicked: console.log('Request ' + index + ' clicked')

                    GridLayout {
                        id: item

                        anchors {
                            left: parent.left
                            right: parent.right
                            leftMargin: constants.paddingSmall
                            rightMargin: constants.paddingSmall
                        }

                        columns: 5

                        Image {
                            Layout.rowSpan: 2
                            Layout.preferredWidth: 32
                            Layout.preferredHeight: 32
                            source: model.type == 0 ? "../../icons/bitcoin.png" : "../../icons/lightning.png"
                        }
                        Label {
                            Layout.fillWidth: true
                            Layout.columnSpan: 2
                            text: model.message
                            font.pixelSize: constants.fontSizeLarge
                        }

                        Label {
                            text: qsTr('Amount: ')
                            font.pixelSize: constants.fontSizeSmall
                        }
                        Label {
                            text: model.amount
                            font.pixelSize: constants.fontSizeSmall
                        }

                        Label {
                            text: qsTr('Timestamp: ')
                            font.pixelSize: constants.fontSizeSmall
                        }
                        Label {
                            text: model.timestamp
                            font.pixelSize: constants.fontSizeSmall
                        }

                        Label {
                            text: qsTr('Status: ')
                            font.pixelSize: constants.fontSizeSmall
                        }
                        Label {
                            text: model.status
                            font.pixelSize: constants.fontSizeSmall
                        }
                    }
                }

                add: Transition {
                    NumberAnimation { properties: 'y'; from: -50; duration: 300 }
                    NumberAnimation { properties: 'opacity'; from: 0; to: 1.0; duration: 700 }
                }
                addDisplaced: Transition {
                    NumberAnimation { properties: 'y'; duration: 100 }
                    NumberAnimation { properties: 'opacity'; to: 1.0; duration: 700 * (1-from) }
                }
            }
        }
    }

    function createRequest(ignoreGaplimit = false) {
        var a = parseFloat(amount.text)
        Daemon.currentWallet.create_invoice(a, message.text, expires.currentValue, false, ignoreGaplimit)
    }

    Connections {
        target: Daemon.currentWallet
        function onRequestCreateSuccess() {
            message.text = ''
            amount.text = ''
        }
        function onRequestCreateError(code, error) {
            if (code == 'gaplimit') {
                var dialog = app.messageDialog.createObject(app, {'text': error, 'yesno': true})
                dialog.yesClicked.connect(function() {
                    createRequest(true)
                })
            } else {
                console.log(error)
                var dialog = app.messageDialog.createObject(app, {'text': error})
            }
            dialog.open()
        }
    }

}
