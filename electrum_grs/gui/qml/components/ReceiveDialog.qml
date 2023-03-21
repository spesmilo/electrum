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

    property string key

    property string _bolt11: request.bolt11
    property string _bip21uri: request.bip21
    property string _address: request.address

    property bool _render_qr: false // delay qr rendering until dialog is shown

    property bool _ispaid: false

    iconSource: Qt.resolvedUrl('../../icons/tab_receive.png')

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
                        PropertyChanges { target: bolt11label; color: Material.accentColor; font.underline: true }
                    },
                    State {
                        name: 'bip21uri'
                        PropertyChanges { target: qrloader; sourceComponent: qri_bip21uri }
                        PropertyChanges { target: bip21label; color: Material.accentColor; font.underline: true }
                    },
                    State {
                        name: 'address'
                        PropertyChanges { target: qrloader; sourceComponent: qri_address }
                        PropertyChanges { target: addresslabel; color: Material.accentColor; font.underline: true }
                    }
                ]

                Rectangle {
                    id: qrbg
                    Layout.alignment: Qt.AlignHCenter
                    Layout.topMargin: constants.paddingSmall
                    Layout.bottomMargin: constants.paddingSmall

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
                            Config.preferredRequestType = rootLayout.state
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
                    Layout.preferredWidth: qrbg.width
                    color: Material.accentColor
                }

                GridLayout {
                    columns: 2
                    Layout.maximumWidth: qrbg.width
                    Layout.alignment: Qt.AlignHCenter

                    Label {
                        text: qsTr('Status')
                        color: Material.accentColor
                    }
                    Label {
                        text: request.status_str
                    }
                    Label {
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
                        visible: !request.message
                        Layout.fillWidth: true
                        text: qsTr('unspecified')
                        color: constants.mutedForeground
                    }
                    Label {
                        text: qsTr('Amount')
                        color: Material.accentColor
                    }
                    FormattedAmount {
                        visible: !request.amount.isEmpty
                        valid: !request.amount.isEmpty
                        amount: request.amount
                    }
                    Label {
                        visible: request.amount.isEmpty
                        text: qsTr('unspecified')
                        color: constants.mutedForeground
                    }
                }

                Rectangle {
                    height: 1
                    Layout.alignment: Qt.AlignHCenter
                    Layout.preferredWidth: qrbg.width
                    color: Material.accentColor
                }

            }

        }

        ButtonContainer {
            id: buttons
            Layout.fillWidth: true

            FlatButton {
                Layout.fillWidth: true
                Layout.preferredWidth: 1

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
                    toaster.show(this, qsTr('Copied!'))
                }
            }
            FlatButton {
                Layout.fillWidth: true
                Layout.preferredWidth: 1

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


    RequestDetails {
        id: request
        wallet: Daemon.currentWallet
        onDetailsChanged: {
            var req_type = Config.preferredRequestType
            if (bolt11 && req_type == 'bolt11') {
                rootLayout.state = 'bolt11'
            } else if (bip21 && req_type == 'bip21uri') {
                rootLayout.state = 'bip21uri'
            } else if (req_type == 'address') {
                rootLayout.state = 'address'
            } else if (bolt11) {
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

    Toaster {
        id: toaster
    }

    Component.onCompleted: {
        request.key = dialog.key
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
