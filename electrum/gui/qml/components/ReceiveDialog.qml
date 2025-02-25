import QtQuick
import QtQuick.Layouts
import QtQuick.Controls
import QtQuick.Controls.Material
import QtQml.Models

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

                TextHighlightPane {
                    Layout.alignment: Qt.AlignHCenter
                    Layout.fillWidth: true

                    ColumnLayout {
                        width: parent.width
                        Rectangle {
                            id: qrbg
                            Layout.alignment: Qt.AlignHCenter
                            Layout.topMargin: constants.paddingSmall
                            Layout.bottomMargin: constants.paddingSmall

                            Layout.preferredWidth: dialog.width * 7/8
                            Layout.preferredHeight: dialog.width * 7/8

                            color: 'white'

                            QRImage {
                                anchors.centerIn: parent
                                qrdata: _bolt11
                                    ? _bolt11
                                    : _bip21uri
                                        ? _bip21uri
                                        : _address
                                render: _render_qr
                                enableToggleText: true
                            }
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
                        AppController.textToClipboard(_bolt11.toLowerCase())
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
                        AppController.doShare(_bolt11.toLowerCase(), qsTr('Payment Request'))
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

    RequestDetails {
        id: request
        wallet: Daemon.currentWallet
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
