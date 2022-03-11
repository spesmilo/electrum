import QtQuick 2.6
import QtQuick.Layouts 1.0
import QtQuick.Controls 2.0
import QtQuick.Controls.Material 2.0

import org.electrum 1.0

Pane {
    id: rootItem
    anchors.fill: parent

    property string title: Daemon.walletName + ' - ' + qsTr('Addresses')

    ColumnLayout {
        id: layout
        width: parent.width
        height: parent.height

        Item {
            width: parent.width
            Layout.fillHeight: true

            ListView {
                id: listview
                width: parent.width
                height: parent.height
                clip: true
                model: Daemon.currentWallet.addressModel

                delegate: AbstractButton {
                    id: delegate
                    width: ListView.view.width
                    height: 30

                    background: Rectangle {
                        color: model.held ? Qt.rgba(1,0,0,0.5) :
                            model.numtx > 0 && model.balance == 0 ? Qt.rgba(1,1,1,0.25) :
                            model.type == 'receive' ? Qt.rgba(0,1,0,0.25) :
                            Qt.rgba(1,0.93,0,0.25)
                        Rectangle {
                            height: 1
                            width: parent.width
                            anchors.top: parent.top
                            border.color: Material.accentColor
                            visible: model.index > 0
                        }
                    }
                    RowLayout {
                        x: 10
                        spacing: 5
                        width: parent.width - 20
                        anchors.verticalCenter: parent.verticalCenter

                        Label {
                            font.pixelSize: 12
                            text: model.type
                        }
                        Label {
                            font.pixelSize: 12
                            font.family: "Courier" // TODO: use system monospace font
                            text: model.address
                            elide: Text.ElideMiddle
                            Layout.maximumWidth: delegate.width / 4
                        }
                        Label {
                            font.pixelSize: 12
                            text: model.label
                            elide: Text.ElideRight
                            Layout.minimumWidth: delegate.width / 4
                            Layout.fillWidth: true
                        }
                        Label {
                            font.pixelSize: 12
                            text: model.balance
                        }
                        Label {
                            font.pixelSize: 12
                            text: model.numtx
                        }
                    }
                }
            }

        }
    }

    Component.onCompleted: Daemon.currentWallet.addressModel.init_model()
}
