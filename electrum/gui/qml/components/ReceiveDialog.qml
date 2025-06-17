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
    iconSource: Qt.resolvedUrl('../../icons/tab_receive.png')

    property string key
    property bool isLightning: request.isLightning

    property string _bolt11: request.bolt11
    property string _bip21uri: request.bip21
    property string _address: request.address
    property bool _render_qr: false // delay qr rendering until dialog is shown

    signal requestPaid

    padding: 0

    function getPaidTxid() {
        return request.paidTxid
    }

    ColumnLayout {
        anchors.fill: parent
        spacing: 0

        Flickable {
            Layout.preferredWidth: parent.width
            Layout.fillHeight: true

            leftMargin: constants.paddingLarge
            rightMargin: constants.paddingLarge

            contentHeight: rootLayout.height
            clip: true
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
                    AppController.textToClipboard(_bolt11
                        ? _bolt11.toLowerCase()
                        : _bip21uri
                            ? _bip21uri
                            : _address
                    )
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
                    AppController.doShare(
                        _bolt11
                            ? _bolt11.toLowerCase()
                            : _bip21uri
                                ? _bip21uri
                                : _address,
                        _bolt11 || _bip21uri
                            ? qsTr('Payment Request')
                            : qsTr('Onchain address')
                    )
                    enabled = true
                }
            }
        }
    }

    RequestDetails {
        id: request
        wallet: Daemon.currentWallet
        onStatusChanged: {
            if (status == RequestDetails.Paid || status == RequestDetails.Unconfirmed) {
                requestPaid()
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
