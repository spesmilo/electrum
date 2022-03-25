import QtQuick 2.6
import QtQuick.Controls 2.3
import QtQuick.Layouts 1.0
import QtQml 2.6

Item {
    id: rootItem

    property string title: Daemon.currentWallet.name

    property QtObject menu: Menu {
        id: menu
        MenuItem {
            icon.color: 'transparent'
            action: Action {
                text: qsTr('Addresses');
                onTriggered: menu.openPage(Qt.resolvedUrl('Addresses.qml'));
                enabled: Daemon.currentWallet != null
                icon.source: '../../icons/tab_addresses.png'
            }
        }
        MenuItem {
            icon.color: 'transparent'
            action: Action {
                text: qsTr('Wallets');
                onTriggered: menu.openPage(Qt.resolvedUrl('Wallets.qml'))
                icon.source: '../../icons/wallet.png'
            }
        }
        MenuItem {
            icon.color: 'transparent'
            action: Action {
                text: qsTr('Network');
                onTriggered: menu.openPage(Qt.resolvedUrl('NetworkStats.qml'))
                icon.source: '../../icons/network.png'
            }
        }
        MenuItem {
            icon.color: 'transparent'
            action: Action {
                text: qsTr('Preferences');
                onTriggered: menu.openPage(Qt.resolvedUrl('Preferences.qml'))
                icon.source: '../../icons/preferences.png'
            }
        }

        function openPage(url) {
            stack.push(url)
            currentIndex = -1
        }
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
            Component.onCompleted: tabbar.setCurrentIndex(1)
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

