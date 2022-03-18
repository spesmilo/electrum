import QtQuick 2.6
import QtQuick.Controls 2.3
import QtQuick.Layouts 1.0
import QtQml 2.6

Item {
    id: rootItem

    property string title: Daemon.walletName

    property QtObject menu: Menu {
        MenuItem { text: qsTr('Addresses'); onTriggered: stack.push(Qt.resolvedUrl('Addresses.qml')); visible: Daemon.currentWallet != null }
        MenuItem { text: qsTr('Wallets'); onTriggered: stack.push(Qt.resolvedUrl('Wallets.qml')) }
        MenuItem { text: qsTr('Network'); onTriggered: stack.push(Qt.resolvedUrl('NetworkStats.qml')) }
    }

    ColumnLayout {
        anchors.centerIn: parent
        width: parent.width
        spacing: 40
        visible: Daemon.currentWallet == null

        Label {
            text: qsTr('No wallet loaded')
            font.pixelSize: 24
            Layout.alignment: Qt.AlignHCenter
        }

        Button {
            text: qsTr('Open/Create Wallet')
            Layout.alignment: Qt.AlignHCenter
            onClicked: {
                stack.push(Qt.resolvedUrl('Wallets.qml'))
            }
        }
    }

    ColumnLayout {
        anchors.fill: parent
        visible: Daemon.currentWallet != null

        TabBar {
            id: tabbar
            Layout.fillWidth: true
            currentIndex: swipeview.currentIndex
            TabButton {
                text: qsTr('Receive')
            }
            TabButton {
                text: qsTr('History')
            }
            TabButton {
                enabled: !Daemon.currentWallet.isWatchOnly
                text: qsTr('Send')
            }
        }

        SwipeView {
            id: swipeview

            Layout.fillHeight: true
            Layout.fillWidth: true
            currentIndex: tabbar.currentIndex

            Item {
                Receive {
                    id: receive
                    anchors.fill: parent
                }
            }

            Item {
                History {
                    id: history
                    anchors.fill: parent
                }
            }


            Item {
                enabled: !Daemon.currentWallet.isWatchOnly
                Send {
                    anchors.fill: parent
                }
            }

        }

    }

    Connections {
        target: Daemon
        function onWalletLoaded() {
            tabbar.setCurrentIndex(1)
        }
    }

}

