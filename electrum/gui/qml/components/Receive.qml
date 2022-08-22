import QtQuick 2.6
import QtQuick.Layouts 1.0
import QtQuick.Controls 2.14
import QtQuick.Controls.Material 2.0
import QtQml.Models 2.1

import org.electrum 1.0

import "controls"

Pane {
    id: rootItem
    visible: Daemon.currentWallet !== undefined

    GridLayout {
        id: form
        width: parent.width
        rowSpacing: constants.paddingSmall
        columnSpacing: constants.paddingSmall
        columns: 4

        Label {
            text: qsTr('Message')
        }

        TextField {
            id: message
            placeholderText: qsTr('Description of payment request')
            Layout.columnSpan: 3
            Layout.fillWidth: true
        }

        Label {
            text: qsTr('Request')
            wrapMode: Text.WordWrap
            Layout.rightMargin: constants.paddingXLarge
        }

        BtcField {
            id: amount
            fiatfield: amountFiat
            Layout.preferredWidth: parent.width /3
        }

        Label {
            text: Config.baseUnit
            color: Material.accentColor
        }

        Item { width: 1; height: 1; Layout.fillWidth: true }

        Item { visible: Daemon.fx.enabled; width: 1; height: 1 }

        FiatField {
            id: amountFiat
            btcfield: amount
            visible: Daemon.fx.enabled
            Layout.preferredWidth: parent.width /3
        }

        Label {
            visible: Daemon.fx.enabled
            text: Daemon.fx.fiatCurrency
            color: Material.accentColor
        }

        Item { visible: Daemon.fx.enabled; width: 1; height: 1; Layout.fillWidth: true }

        Label {
            text: qsTr('Expires after')
            Layout.fillWidth: false
        }

        ElComboBox {
            id: expires
            Layout.columnSpan: 2

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
                    expiresmodel.append({'text': qsTr('1 month'), 'value': 31*24*60*60})
                    expiresmodel.append({'text': qsTr('Never'), 'value': 0})
                    expires.currentIndex = 0
                }
            }
        }

        Item { width: 1; height: 1; Layout.fillWidth: true }

        Button {
            Layout.columnSpan: 4
            Layout.alignment: Qt.AlignHCenter
            text: qsTr('Create Request')
            icon.source: '../../icons/qrcode.png'
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
                        font.pixelSize: constants.fontSizeLarge
                        color: Material.accentColor
                    }
                }
            }

            ListView {
                id: listview
                Layout.fillHeight: true
                Layout.fillWidth: true
                clip: true

                model: DelegateModel {
                    id: delegateModel
                    model: Daemon.currentWallet.requestModel
                    delegate: InvoiceDelegate {
                        onClicked: {
                            var dialog = requestdialog.createObject(app, {'modelItem': model})
                            dialog.open()
                        }
                    }
                }

                remove: Transition {
                    NumberAnimation { properties: 'scale'; to: 0.75; duration: 300 }
                    NumberAnimation { properties: 'opacity'; to: 0; duration: 300 }
                }
                removeDisplaced: Transition {
                    SequentialAnimation {
                        PauseAnimation { duration: 200 }
                        SpringAnimation { properties: 'y'; duration: 100; spring: 5; damping: 0.5; mass: 2 }
                    }
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

    Component {
        id: requestdialog
        RequestDialog {
            onClosed: destroy()
        }
    }

    function createRequest(ignoreGaplimit = false) {
        var qamt = Config.unitsToSats(amount.text)
        if (qamt.satsInt > Daemon.currentWallet.lightningCanReceive.satsInt) {
            console.log('Creating OnChain request')
            Daemon.currentWallet.create_request(qamt, message.text, expires.currentValue, false, ignoreGaplimit)
        } else {
            console.log('Creating Lightning request')
            Daemon.currentWallet.create_request(qamt, message.text, expires.currentValue, true)
        }
    }

    Connections {
        target: Daemon.currentWallet
        function onRequestCreateSuccess() {
            message.text = ''
            amount.text = ''
            var dialog = requestdialog.createObject(app, {
                'modelItem': delegateModel.items.get(0).model
            })
            dialog.open()
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
        function onRequestStatusChanged(key, status) {
            Daemon.currentWallet.requestModel.updateRequest(key, status)
        }
    }

}
