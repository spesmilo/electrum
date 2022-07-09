import QtQuick 2.6
import QtQuick.Controls 2.3
import QtQuick.Layouts 1.0
import QtQml 2.6

Item {
    id: rootItem

    property string title: Daemon.currentWallet ? Daemon.currentWallet.name : ''

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
                text: qsTr('Channels');
                enabled: Daemon.currentWallet != null && Daemon.currentWallet.isLightning
                onTriggered: menu.openPage(Qt.resolvedUrl('Channels.qml'))
                icon.source: '../../icons/lightning.png'
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

        MenuItem {
            icon.color: 'transparent'
            action: Action {
                text: qsTr('About');
                onTriggered: menu.openPage(Qt.resolvedUrl('About.qml'))
                icon.source: '../../icons/electrum.png'
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
        spacing: 2*constants.paddingXLarge
        visible: Daemon.currentWallet == null

        Label {
            text: qsTr('No wallet loaded')
            font.pixelSize: constants.fontSizeXXLarge
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

        SwipeView {
            id: swipeview

            Layout.fillHeight: true
            Layout.fillWidth: true
            currentIndex: tabbar.currentIndex

            Item {
                Loader {
                    anchors.fill: parent
                    Receive {
                        id: receive
                        anchors.fill: parent
                    }
                }
            }

            Item {
                Loader {
                    anchors.fill: parent
                    History {
                        id: history
                        anchors.fill: parent
                    }
                }
            }


            Item {
                enabled: !Daemon.currentWallet.isWatchOnly
                Loader {
                    anchors.fill: parent
                    Send {
                        anchors.fill: parent
                    }
                }
            }

        }

        TabBar {
            id: tabbar
            position: TabBar.Footer
            Layout.fillWidth: true
            currentIndex: swipeview.currentIndex
            TabButton {
                text: qsTr('Receive')
                font.pixelSize: constants.fontSizeLarge
            }
            TabButton {
                text: qsTr('History')
                font.pixelSize: constants.fontSizeLarge
            }
            TabButton {
                enabled: !Daemon.currentWallet.isWatchOnly
                text: qsTr('Send')
                font.pixelSize: constants.fontSizeLarge
            }
            Component.onCompleted: tabbar.setCurrentIndex(1)
        }

    }

    Connections {
        target: Daemon
        function onWalletLoaded() {
            tabbar.setCurrentIndex(1)
        }
    }

}

