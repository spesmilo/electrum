import QtQuick 2.6
import QtQuick.Layouts 1.0
import QtQuick.Controls 2.0

Item {
    property string title: 'Wallets'

    ListView {
        width: parent.width
        height: 200
        model: Daemon.activeWallets

        delegate: Item {
            width: ListView.view.width

            RowLayout {
                x: 20
                spacing: 20

                Image {
                    source: "../../../gui/kivy/theming/light/wallet.png"
                }

                Label {
                    font.pointSize: 13
                    text: model.display
                }
            }
        }
    }

}
