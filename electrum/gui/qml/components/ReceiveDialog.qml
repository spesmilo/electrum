import QtQuick 2.6
import QtQuick.Layouts 1.0
import QtQuick.Controls 2.14
import QtQuick.Controls.Material 2.0
import QtQml.Models 2.1

import org.electrum 1.0

import "controls"

ElDialog {
    id: dialog

    property string _bolt11
    property string _bip21uri
    property string _address

    property bool _render_qr: false // delay qr rendering until dialog is shown

    parent: Overlay.overlay
    modal: true
    standardButtons: Dialog.Close

    width: parent.width
    height: parent.height

    Overlay.modal: Rectangle {
        color: "#aa000000"
    }

    ColumnLayout {
        id: rootLayout
        width: parent.width
        spacing: constants.paddingMedium

        states: [
            State {
                name: 'bolt11'
                PropertyChanges { target: qrloader; sourceComponent: qri_bolt11 }
                PropertyChanges { target: bolt11label; font.bold: true }
            },
            State {
                name: 'bip21uri'
                PropertyChanges { target: qrloader; sourceComponent: qri_bip21uri }
                PropertyChanges { target: bip21label; font.bold: true }
            },
            State {
                name: 'address'
                PropertyChanges { target: qrloader; sourceComponent: qri_address }
                PropertyChanges { target: addresslabel; font.bold: true }
            }
        ]

        Rectangle {
            height: 1
            Layout.fillWidth: true
            color: Material.accentColor
        }

        Item {
            Layout.alignment: Qt.AlignHCenter
            Layout.topMargin: constants.paddingSmall
            Layout.bottomMargin: constants.paddingSmall

            Layout.preferredWidth: qrloader.width
            Layout.preferredHeight: qrloader.height

            Loader {
                id: qrloader
                Component {
                    id: qri_bolt11
                    QRImage {
                        qrdata: _bolt11
                        render: _render_qr
                    }
                }
                Component {
                    id: qri_bip21uri
                    QRImage {
                        qrdata: _bip21uri
                        render: _render_qr
                    }
                }
                Component {
                    id: qri_address
                    QRImage {
                        qrdata: _address
                        render: _render_qr
                    }
                }
            }

            MouseArea {
                anchors.fill: parent
                onClicked: {
                    if (rootLayout.state == 'bolt11') {
                        if (_bip21uri != '')
                            rootLayout.state = 'bip21uri'
                        else if (_address != '')
                            rootLayout.state = 'address'
                    } else if (rootLayout.state == 'bip21uri') {
                        if (_address != '')
                            rootLayout.state = 'address'
                        else if (_bolt11 != '')
                            rootLayout.state = 'bolt11'
                    } else if (rootLayout.state == 'address') {
                        if (_bolt11 != '')
                            rootLayout.state = 'bolt11'
                        else if (_bip21uri != '')
                            rootLayout.state = 'bip21uri'
                    }
                }
            }
        }

        RowLayout {
            Layout.alignment: Qt.AlignHCenter
            spacing: constants.paddingLarge
            Label {
                id: bolt11label
                text: qsTr('BOLT11')
                color: _bolt11 ? Material.foreground : constants.mutedForeground
            }
            Rectangle {
                Layout.preferredWidth: constants.paddingXXSmall
                Layout.preferredHeight: constants.paddingXXSmall
                radius: constants.paddingXXSmall / 2
                color: Material.accentColor
            }
            Label {
                id: bip21label
                text: qsTr('BIP21')
                color: _bip21uri ? Material.foreground : constants.mutedForeground
            }
            Rectangle {
                Layout.preferredWidth: constants.paddingXXSmall
                Layout.preferredHeight: constants.paddingXXSmall
                radius: constants.paddingXXSmall / 2
                color: Material.accentColor
            }
            Label {
                id: addresslabel
                text: qsTr('ADDRESS')
                color: _address ? Material.foreground : constants.mutedForeground
            }
        }

        Rectangle {
            height: 1
            Layout.fillWidth: true
            color: Material.accentColor
        }

// aaaaaaaaaaaaaaaaaaaa


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
        function onRequestCreateSuccess(key) {
            message.text = ''
            amount.text = ''
            var dialog = requestdialog.createObject(app, { key: key })
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

    Component.onCompleted: {
        _address = '1234567890'
        rootLayout.state = 'address'
    }

    // hack. delay qr rendering until dialog is shown
    Connections {
        target: dialog.enter
        function onRunningChanged() {
            if (!dialog.enter.running) {
                dialog._render_qr = true
            }
        }
    }

}
