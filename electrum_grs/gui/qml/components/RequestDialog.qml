import QtQuick 2.6
import QtQuick.Layouts 1.0
import QtQuick.Controls 2.14
import QtQuick.Controls.Material 2.0

import org.electrum 1.0

Dialog {
    id: dialog
    title: qsTr('Payment Request')

    property var modelItem

    property string _bip21uri

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

        GridLayout {
            id: rootLayout
            width: parent.width
            rowSpacing: constants.paddingMedium
            columns: 5

            Rectangle {
                height: 1
                Layout.fillWidth: true
                Layout.columnSpan: 5
                color: Material.accentColor
            }

            Image {
                id: qr
                Layout.columnSpan: 5
                Layout.alignment: Qt.AlignHCenter
                Layout.topMargin: constants.paddingSmall
                Layout.bottomMargin: constants.paddingSmall

                Rectangle {
                    property int size: 57 // should be qr pixel multiple
                    color: 'white'
                    x: (parent.width - size) / 2
                    y: (parent.height - size) / 2
                    width: size
                    height: size

                    Image {

                        source: '../../icons/electrum.png'
                        x: 1
                        y: 1
                        width: parent.width - 2
                        height: parent.height - 2
                        scale: 0.9
                    }
                }
            }

            Rectangle {
                height: 1
                Layout.fillWidth: true
                Layout.columnSpan: 5
                color: Material.accentColor
            }

            RowLayout {
                Layout.columnSpan: 5
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
            Label {
                visible: modelItem.message != ''
                text: qsTr('Description')
            }
            Label {
                visible: modelItem.message != ''
                Layout.columnSpan: 4
                Layout.fillWidth: true
                wrapMode: Text.Wrap
                text: modelItem.message
                font.pixelSize: constants.fontSizeLarge
            }

            Label {
                visible: modelItem.amount.satsInt != 0
                text: qsTr('Amount')
            }
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
                Layout.columnSpan: 2
                text: Daemon.fx.enabled
                        ? '(' + Daemon.fx.fiatValue(modelItem.amount, false) + ' ' + Daemon.fx.fiatCurrency + ')'
                        : ''
                font.pixelSize: constants.fontSizeMedium
                wrapMode: Text.Wrap
            }

            Label {
                text: qsTr('Address')
                visible: !modelItem.is_lightning
            }
            Label {
                Layout.fillWidth: true
                Layout.columnSpan: 3
                visible: !modelItem.is_lightning
                font.family: FixedFont
                font.pixelSize: constants.fontSizeLarge
                wrapMode: Text.WrapAnywhere
                text: modelItem.address
            }
            ToolButton {
                icon.source: '../../icons/copy_bw.png'
                visible: !modelItem.is_lightning
                onClicked: {
                    AppController.textToClipboard(modelItem.address)
                }
            }

            Label {
                text: qsTr('Status')
            }
            Label {
                Layout.columnSpan: 4
                Layout.fillWidth: true
                font.pixelSize: constants.fontSizeLarge
                text: modelItem.status_str
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
            qr.source = 'image://qrgen/' + _bip21uri
        } else {
            qr.source = 'image://qrgen/' + modelItem.lightning_invoice
        }
    }

    Bitcoin {
        id: bitcoin
    }
}
