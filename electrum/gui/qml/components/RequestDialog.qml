import QtQuick 2.6
import QtQuick.Layouts 1.0
import QtQuick.Controls 2.14
import QtQuick.Controls.Material 2.0

import org.electrum 1.0

import "controls"

Dialog {
    id: dialog
    title: qsTr('Payment Request')

    property var modelItem

    property string _bip21uri
    property string _bolt11

    parent: Overlay.overlay
    modal: true
    standardButtons: Dialog.Close

    width: parent.width
    height: parent.height

    Overlay.modal: Rectangle {
        color: "#aa000000"
    }

    header: RowLayout {
        width: dialog.width
        Label {
            Layout.fillWidth: true
            text: dialog.title
            visible: dialog.title
            elide: Label.ElideRight
            padding: constants.paddingXLarge
            bottomPadding: 0
            font.bold: true
            font.pixelSize: constants.fontSizeMedium
        }
    }

    Flickable {
        anchors.fill: parent
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
                    PropertyChanges { target: bolt11label; font.bold: true }
                },
                State {
                    name: 'bip21uri'
                    PropertyChanges { target: qrloader; sourceComponent: qri_bip21uri }
                    PropertyChanges { target: bip21label; font.bold: true }
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
                        id: qri_bip21uri
                        QRImage {
                            qrdata: _bip21uri
                        }
                    }
                    Component {
                        id: qri_bolt11
                        QRImage {
                            qrdata: _bolt11
                        }
                    }
                }

                MouseArea {
                    anchors.fill: parent
                    onClicked: {
                        if (rootLayout.state == 'bolt11') {
                            if (_bip21uri != '')
                                rootLayout.state = 'bip21uri'
                        } else if (rootLayout.state == 'bip21uri') {
                            if (_bolt11 != '')
                                rootLayout.state = 'bolt11'
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
                    text: qsTr('BIP21 URI')
                    color: _bip21uri ? Material.foreground : constants.mutedForeground
                }
            }

            Rectangle {
                height: 1
                Layout.fillWidth: true
                color: Material.accentColor
            }

            RowLayout {
                Layout.alignment: Qt.AlignHCenter
                Button {
                    icon.source: '../../icons/delete.png'
                    text: qsTr('Delete')
                    onClicked: {
                        Daemon.currentWallet.delete_request(modelItem.key)
                        dialog.close()
                    }
                }
                Button {
                    icon.source: '../../icons/copy_bw.png'
                    icon.color: 'transparent'
                    text: 'Copy'
                    onClicked: {
                        if (modelItem.is_lightning)
                            AppController.textToClipboard(modelItem.lightning_invoice)
                        else
                            AppController.textToClipboard(_bip21uri)

                    }
                }
                Button {
                    icon.source: '../../icons/share.png'
                    text: 'Share'
                    onClicked: {
                        enabled = false
                        if (modelItem.is_lightning)
                            AppController.doShare(modelItem.lightning_invoice, qsTr('Payment Request'))
                        else
                            AppController.doShare(_bip21uri, qsTr('Payment Request'))
                        enabled = true
                    }
                }
            }

            GridLayout {
                columns: 2

                Label {
                    visible: modelItem.message != ''
                    text: qsTr('Description')
                }
                Label {
                    visible: modelItem.message != ''
                    Layout.fillWidth: true
                    wrapMode: Text.Wrap
                    text: modelItem.message
                    font.pixelSize: constants.fontSizeLarge
                }

                Label {
                    visible: modelItem.amount.satsInt != 0
                    text: qsTr('Amount')
                }
                RowLayout {
                    Label {
                        visible: modelItem.amount.satsInt != 0
                        text: Config.formatSats(modelItem.amount)
                        font.family: FixedFont
                        font.pixelSize: constants.fontSizeLarge
                        font.bold: true
                    }
                    Label {
                        visible: modelItem.amount.satsInt != 0
                        text: Config.baseUnit
                        color: Material.accentColor
                        font.pixelSize: constants.fontSizeLarge
                    }

                    Label {
                        id: fiatValue
                        visible: modelItem.amount.satsInt != 0
                        Layout.fillWidth: true
                        text: Daemon.fx.enabled
                                ? '(' + Daemon.fx.fiatValue(modelItem.amount, false) + ' ' + Daemon.fx.fiatCurrency + ')'
                                : ''
                        font.pixelSize: constants.fontSizeMedium
                        wrapMode: Text.Wrap
                    }
                }

                Label {
                    text: qsTr('Address')
                    visible: !modelItem.is_lightning
                }

                RowLayout {
                    visible: !modelItem.is_lightning
                    Label {
                        Layout.fillWidth: true
                        font.family: FixedFont
                        font.pixelSize: constants.fontSizeLarge
                        wrapMode: Text.WrapAnywhere
                        text: modelItem.address
                    }
                    ToolButton {
                        icon.source: '../../icons/copy_bw.png'
                        onClicked: {
                            AppController.textToClipboard(modelItem.address)
                        }
                    }
                }

                Label {
                    text: qsTr('Status')
                }
                Label {
                    Layout.fillWidth: true
                    font.pixelSize: constants.fontSizeLarge
                    text: modelItem.status_str
                }
            }
        }
    }

    Connections {
        target: Daemon.currentWallet
        function onRequestStatusChanged(key, status) {
            if (key != modelItem.key)
                return
            modelItem = Daemon.currentWallet.get_request(key)
        }
    }

    Component.onCompleted: {
        if (!modelItem.is_lightning) {
            _bip21uri = bitcoin.create_bip21_uri(modelItem.address, modelItem.amount, modelItem.message, modelItem.timestamp, modelItem.expiration - modelItem.timestamp)
            rootLayout.state = 'bip21uri'
        } else {
            _bolt11 = modelItem.lightning_invoice
            rootLayout.state = 'bolt11'
            if (modelItem.address != '') {
                _bip21uri = bitcoin.create_bip21_uri(modelItem.address, modelItem.amount, modelItem.message, modelItem.timestamp, modelItem.expiration - modelItem.timestamp)
                console.log('BIP21:' + _bip21uri)
            }
        }
    }

    Bitcoin {
        id: bitcoin
    }
}
