import QtQuick 2.6
import QtQuick.Layouts 1.0
import QtQuick.Controls 2.14
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
        columns: 4

        Label {
            text: qsTr('Message')
        }

        TextField {
            id: message
            Layout.columnSpan: 3
            Layout.fillWidth: true
        }

        Label {
            text: qsTr('Requested Amount')
            wrapMode: Text.WordWrap
            Layout.preferredWidth: 50 // trigger wordwrap
            Layout.rightMargin: constants.paddingXLarge
            Layout.rowSpan: 2
        }

        TextField {
            id: amount
            font.family: FixedFont
            Layout.fillWidth: true
        }

        Label {
            text: Config.baseUnit
            color: Material.accentColor
        }

        ColumnLayout {
            Layout.rowSpan: 2
            Layout.preferredWidth: rootItem.width /3
            Layout.leftMargin: constants.paddingXLarge

            Label {
                text: qsTr('Expires after')
                Layout.fillWidth: false
            }

            ComboBox {
                id: expires
                Layout.fillWidth: true
                textRole: 'text'
                valueRole: 'value'

                model: ListModel {
                    id: expiresmodel
                    Component.onCompleted: {
                        // we need to fill the model like this, as ListElement can't evaluate script
                        expiresmodel.append({'text': qsTr('10 minutes'), 'value': 10*60})
                        expiresmodel.append({'text': qsTr('1 hour'), 'value': 60*60})
                        expiresmodel.append({'text': qsTr('1 day'), 'value': 24*60*60})
                        expiresmodel.append({'text': qsTr('1 week'), 'value': 7*24*60*60})
                        expiresmodel.append({'text': qsTr('1 month'), 'value': 31*7*24*60*60})
                        expiresmodel.append({'text': qsTr('Never'), 'value': 0})
                        expires.currentIndex = 0
                    }
                }
            }
        }

        TextField {
            id: amountFiat
            font.family: FixedFont
            Layout.fillWidth: true
        }

        Label {
            text: qsTr('EUR')
            color: Material.accentColor
        }

        RowLayout {
            Layout.columnSpan: 4
            Layout.alignment: Qt.AlignHCenter
            CheckBox {
                id: cb_onchain
                text: qsTr('Onchain')
                checked: true
                contentItem: RowLayout {
                    Text {
                        text: cb_onchain.text
                        font: cb_onchain.font
                        opacity: enabled ? 1.0 : 0.3
                        color: Material.foreground
                        verticalAlignment: Text.AlignVCenter
                        leftPadding: cb_onchain.indicator.width + cb_onchain.spacing
                    }
                    Image {
                        x: 16
                        Layout.preferredWidth: 16
                        Layout.preferredHeight: 16
                        source: '../../icons/bitcoin.png'
                    }
                }
            }

            CheckBox {
                id: cb_lightning
                text: qsTr('Lightning')
                enabled: false
                contentItem: RowLayout {
                    Text {
                        text: cb_lightning.text
                        font: cb_lightning.font
                        opacity: enabled ? 1.0 : 0.3
                        color: Material.foreground
                        verticalAlignment: Text.AlignVCenter
                        leftPadding: cb_lightning.indicator.width + cb_lightning.spacing
                    }
                    Image {
                        x: 16
                        Layout.preferredWidth: 16
                        Layout.preferredHeight: 16
                        source: '../../icons/lightning.png'
                    }
                }
            }
        }

        Button {
            Layout.columnSpan: 4
            Layout.alignment: Qt.AlignHCenter
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

        background: PaneInsetBackground {}

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

                    font.pixelSize: constants.fontSizeSmall // set default font size for child controls

                    GridLayout {
                        id: item

                        anchors {
                            left: parent.left
                            right: parent.right
                            leftMargin: constants.paddingSmall
                            rightMargin: constants.paddingSmall
                        }

                        columns: 5

                        Rectangle {
                            Layout.columnSpan: 5
                            Layout.fillWidth: true
                            Layout.preferredHeight: constants.paddingTiny
                            color: 'transparent'
                        }
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
                            elide: Text.ElideRight
                            font.pixelSize: constants.fontSizeLarge
                        }

                        Label {
                            text: qsTr('Amount: ')
                        }
                        Label {
                            id: amount
                            text: Config.formatSats(model.amount, true)
                            font.family: FixedFont
                        }

                        Label {
                            text: qsTr('Timestamp: ')
                        }
                        Label {
                            text: model.timestamp
                        }

                        Label {
                            text: qsTr('Status: ')
                        }
                        Label {
                            text: model.status
                        }
                        Rectangle {
                            Layout.columnSpan: 5
                            Layout.fillWidth: true
                            Layout.preferredHeight: constants.paddingTiny
                            color: 'transparent'
                        }
                    }

                    Connections {
                        target: Config
                        function onBaseUnitChanged() {
                            amount.text = Config.formatSats(model.amount, true)
                        }
                        function onThousandsSeparatorChanged() {
                            amount.text = Config.formatSats(model.amount, true)
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

                ScrollIndicator.vertical: ScrollIndicator { }
            }
        }
    }

    // make clicking the dialog background move the scope away from textedit fields
    // so the keyboard goes away
    MouseArea {
        anchors.fill: parent
        z: -1000
        onClicked: parkFocus.focus = true
        FocusScope { id: parkFocus }
    }

    function createRequest(ignoreGaplimit = false) {
        var a = Config.unitsToSats(amount.text)
        Daemon.currentWallet.create_invoice(a, message.text, expires.currentValue, false, ignoreGaplimit)
    }

    Connections {
        target: Daemon.currentWallet
        function onRequestCreateSuccess() {
            message.text = ''
            amount.text = ''
//             var dialog = app.showAsQrDialog.createObject(app, {'text': 'test'})
//             dialog.open()
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
