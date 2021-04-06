import QtQuick 2.6
import QtQuick.Layouts 1.0
import QtQuick.Controls 2.0

Item {
    property string title: 'Wallets'

    anchors.fill: parent

    ListView {
        width: parent.width
        height: parent.height
        model: Daemon.availableWallets

        delegate: Item {
            width: ListView.view.width
            height: 50

            RowLayout {
                x: 20
                spacing: 20

                Image {
                    source: "../../../gui/kivy/theming/light/wallet.png"
                }

                Label {
                    font.pointSize: model.active ? 14 : 13
                    font.bold: model.active
                    text: model.name
                    Layout.fillWidth: true
                }

            }

            MouseArea {
                anchors.fill: parent
                onClicked: openMenu()
            }
        }
    }

}
