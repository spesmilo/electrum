import QtQuick 2.6
import QtQuick.Layouts 1.0
import QtQuick.Controls 2.14
import QtQuick.Controls.Material 2.0
import QtQml.Models 2.1

import org.electrum 1.0

import "controls"

ElDialog {
    id: dialog

    title: qsTr('Receive Payment')

    property string _bolt11: request.bolt11
    property string _bip21uri: request.bip21
    property string _address: request.address

    property bool _render_qr: false // delay qr rendering until dialog is shown

    property bool _ispaid: false

    parent: Overlay.overlay
    modal: true
    standardButtons: Dialog.Close

    Overlay.modal: Rectangle {
        color: "#aa000000"
    }

    padding: 0

    ColumnLayout {
        visible: !_ispaid
        anchors.fill: parent
        spacing: 0

        Flickable {
            Layout.preferredWidth: parent.width
            Layout.fillHeight: true

            leftMargin: constants.paddingLarge
            rightMargin: constants.paddingLarge

            contentHeight: rootLayout.height
            clip:true
            interactive: height < contentHeight

            ColumnLayout {
                id: rootLayout
                width: parent.width
                spacing: constants.paddingMedium

                states: [
                    State {
                        name: 'bolt11'
                        PropertyChanges { target: qrloader; sourceComponent: qri_bolt11 }
                        PropertyChanges { target: bolt11label; color: Material.accentColor }
                    },
                    State {
                        name: 'bip21uri'
                        PropertyChanges { target: qrloader; sourceComponent: qri_bip21uri }
                        PropertyChanges { target: bip21label; color: Material.accentColor }
                    },
                    State {
                        name: 'address'
                        PropertyChanges { target: qrloader; sourceComponent: qri_address }
                        PropertyChanges { target: addresslabel; color: Material.accentColor }
                    }
                ]

                Rectangle {
                    Layout.alignment: Qt.AlignHCenter
                    Layout.topMargin: constants.paddingSmall
                    Layout.bottomMargin: constants.paddingSmall

                    // Layout.preferredWidth: qrloader.width
                    // Layout.preferredHeight: qrloader.height
                    Layout.preferredWidth: dialog.width * 7/8
                    Layout.preferredHeight: dialog.width * 7/8

                    color: 'white'

                    Loader {
                        id: qrloader
                        anchors.centerIn: parent
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
                        text: qsTr('Lightning')
                        color: _bolt11 ? Material.foreground : constants.mutedForeground
                        MouseArea {
                            anchors.fill: parent
                            enabled: _bolt11
                            onClicked: rootLayout.state = 'bolt11'
                        }
                    }
                    Rectangle {
                        Layout.preferredWidth: constants.paddingXXSmall
                        Layout.preferredHeight: constants.paddingXXSmall
                        radius: constants.paddingXXSmall / 2
                        color: Material.accentColor
                    }
                    Label {
                        id: bip21label
                        text: qsTr('URI')
                        color: _bip21uri ? Material.foreground : constants.mutedForeground
                        MouseArea {
                            anchors.fill: parent
                            enabled: _bip21uri
                            onClicked: rootLayout.state = 'bip21uri'
                        }
                    }
                    Rectangle {
                        Layout.preferredWidth: constants.paddingXXSmall
                        Layout.preferredHeight: constants.paddingXXSmall
                        radius: constants.paddingXXSmall / 2
                        color: Material.accentColor
                    }
                    Label {
                        id: addresslabel
                        text: qsTr('Address')
                        color: _address ? Material.foreground : constants.mutedForeground
                        MouseArea {
                            anchors.fill: parent
                            enabled: _address
                            onClicked: rootLayout.state = 'address'
                        }
                    }
                }

                Rectangle {
                    height: 1
                    Layout.alignment: Qt.AlignHCenter
                    Layout.preferredWidth: buttons.width
                    color: Material.accentColor
                }

                GridLayout {
                    columns: 2
                    visible: request.message || !request.amount.isEmpty
                    Layout.maximumWidth: qrloader.width
                    Layout.alignment: Qt.AlignHCenter

                    Label {
                        visible: request.message
                        text: qsTr('Message')
                        color: Material.accentColor
                    }
                    Label {
                        visible: request.message
                        Layout.fillWidth: true
                        text: request.message
                        wrapMode: Text.Wrap
                    }
                    Label {
                        visible: !request.amount.isEmpty
                        text: qsTr('Amount')
                        color: Material.accentColor
                    }
                    RowLayout {
                        visible: !request.amount.isEmpty
                        Label {
                            text: Config.formatSats(request.amount)
                            font.family: FixedFont
                            font.pixelSize: constants.fontSizeMedium
                            font.bold: true
                        }
                        Label {
                            text: Config.baseUnit
                            color: Material.accentColor
                            font.pixelSize: constants.fontSizeMedium
                        }
                        Label {
                            visible: Daemon.fx.enabled
                            text: '(' + Daemon.fx.fiatValue(request.amount, false) + ' ' + Daemon.fx.fiatCurrency + ')'
                            font.pixelSize: constants.fontSizeMedium
                        }
                    }
                }

                Rectangle {
                    visible: request.message || !request.amount.isEmpty
                    height: 1
                    Layout.alignment: Qt.AlignHCenter
                    Layout.preferredWidth: buttons.width
                    color: Material.accentColor
                }

                RowLayout {
                    id: buttons
                    Layout.alignment: Qt.AlignHCenter
                    FlatButton {
                        icon.source: '../../icons/copy_bw.png'
                        icon.color: 'transparent'
                        text: 'Copy'
                        onClicked: {
                            if (request.isLightning && rootLayout.state == 'bolt11')
                                AppController.textToClipboard(_bolt11)
                            else if (rootLayout.state == 'bip21uri')
                                AppController.textToClipboard(_bip21uri)
                            else
                                AppController.textToClipboard(_address)
                        }
                    }
                    FlatButton {
                        icon.source: '../../icons/share.png'
                        text: 'Share'
                        onClicked: {
                            enabled = false
                            if (request.isLightning && rootLayout.state == 'bolt11')
                                AppController.doShare(_bolt11, qsTr('Payment Request'))
                            else if (rootLayout.state == 'bip21uri')
                                AppController.doShare(_bip21uri, qsTr('Payment Request'))
                            else
                                AppController.doShare(_address, qsTr('Onchain address'))

                            enabled = true
                        }
                    }
                    FlatButton {
                        Layout.alignment: Qt.AlignHCenter
                        icon.source: '../../icons/pen.png'
                        text: qsTr('Edit')
                        onClicked: receiveDetailsDialog.open()
                    }
                }
            }

        }
    }

    ColumnLayout {
        visible: _ispaid
        anchors.centerIn: parent
        states: [
            State {
                name: 'paid'
                when: _ispaid
            }
        ]
        transitions: [
            Transition {
                from: ''
                to: 'paid'
                NumberAnimation { target: paidIcon; properties: 'opacity'; from: 0; to: 1; duration: 200 }
                NumberAnimation { target: paidIcon; properties: 'scale'; from: 0; to: 1; duration: 500; easing.type: Easing.OutBack; easing.overshoot: 10 }
            }
        ]
        Image {
            id: paidIcon
            Layout.alignment: Qt.AlignHCenter
            Layout.preferredWidth: constants.iconSizeXXLarge
            Layout.preferredHeight: constants.iconSizeXXLarge
            source: '../../icons/confirmed.png'
        }
        Label {
            Layout.alignment: Qt.AlignHCenter
            text: qsTr('Paid!')
            font.pixelSize: constants.fontSizeXXLarge
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
        var qamt = Config.unitsToSats(receiveDetailsDialog.amount)
        if (qamt.satsInt > Daemon.currentWallet.lightningCanReceive.satsInt) {
            console.log('Creating OnChain request')
            Daemon.currentWallet.createRequest(qamt, receiveDetailsDialog.description, receiveDetailsDialog.expiry, false, ignoreGaplimit)
        } else {
            console.log('Creating Lightning request')
            Daemon.currentWallet.createRequest(qamt, receiveDetailsDialog.description, receiveDetailsDialog.expiry, true)
        }
    }

    function createDefaultRequest(ignoreGaplimit = false) {
        console.log('Creating default request')
        Daemon.currentWallet.createDefaultRequest(ignoreGaplimit)
    }

    Connections {
        target: Daemon.currentWallet
        function onRequestCreateSuccess(key) {
            request.key = key
        }
        function onRequestCreateError(code, error) {
            if (code == 'gaplimit') {
                var dialog = app.messageDialog.createObject(app, {'text': error, 'yesno': true})
                dialog.yesClicked.connect(function() {
                    createDefaultRequest(true)
                })
            } else {
                console.log(error)
                var dialog = app.messageDialog.createObject(app, {'text': error})
            }
            dialog.open()
        }
    }

    RequestDetails {
        id: request
        wallet: Daemon.currentWallet
        onDetailsChanged: {
            if (bolt11) {
                rootLayout.state = 'bolt11'
            } else if (bip21) {
                rootLayout.state = 'bip21uri'
            } else {
                rootLayout.state = 'address'
            }
        }
        onStatusChanged: {
            if (status == RequestDetails.Paid || status == RequestDetails.Unconfirmed) {
                _ispaid = true
            }
        }
    }

    ReceiveDetailsDialog {
        id: receiveDetailsDialog

        width: parent.width * 0.9
        anchors.centerIn: parent

        onAccepted: {
            console.log('accepted')
            Daemon.currentWallet.delete_request(request.key)
            createRequest()
        }
        onRejected: {
            console.log('rejected')
        }
    }

    Component.onCompleted: {
        createDefaultRequest()
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
