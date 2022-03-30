import QtQuick 2.6
import QtQuick.Layouts 1.0
import QtQuick.Controls 2.3
import QtQuick.Controls.Material 2.0

import QtQml 2.6
import QtMultimedia 5.6

ApplicationWindow
{
    id: app
    visible: true

    // dimensions ignored on android
    width: 480
    height: 800

    Material.theme: Material.Dark
    Material.primary: Material.Indigo
    Material.accent: Material.LightBlue

    property QtObject constants: Constants {}

    property alias stack: mainStackView

    header: ToolBar {
        id: toolbar
        RowLayout {
            anchors.fill: parent

            ToolButton {
                text: qsTr("‹")
                enabled: stack.depth > 1
                onClicked: stack.pop()
            }

            Label {
                text: stack.currentItem.title
                elide: Label.ElideRight
                horizontalAlignment: Qt.AlignHCenter
                verticalAlignment: Qt.AlignVCenter
                Layout.fillWidth: true
                font.pixelSize: constants.fontSizeMedium
                font.bold: true
            }

            Item {
                visible: Network.isTestNet
                width: column.width
                height: column.height
                MouseArea {
                    anchors.fill: parent
                    onClicked: {
                        var dialog = app.messageDialog.createObject(app, {'text':
                            'Electrum is currently on ' + Network.networkName + ''
                        })
                        dialog.open()
                    }

                }

                ColumnLayout {
                    id: column
                    spacing: 0
                    Image {
                        Layout.alignment: Qt.AlignHCenter
                        Layout.preferredWidth: constants.iconSizeSmall
                        Layout.preferredHeight: constants.iconSizeSmall
                        source: "../../icons/info.png"
                    }

                    Label {
                        id: networkNameLabel
                        text: Network.networkName
                        color: Material.accentColor
                        font.pixelSize: constants.fontSizeXSmall
                    }
                }
            }

            Image {
                Layout.preferredWidth: constants.iconSizeSmall
                Layout.preferredHeight: constants.iconSizeSmall
                visible: Daemon.currentWallet.isWatchOnly
                source: '../../icons/eye1.png'
                scale: 1.5
            }

            Image {
                Layout.preferredWidth: constants.iconSizeSmall
                Layout.preferredHeight: constants.iconSizeSmall
                source: Network.status == 'connecting' || Network.status == 'disconnected'
                    ? '../../icons/status_disconnected.png'
                    : Daemon.currentWallet.isUptodate
                        ? '../../icons/status_connected.png'
                        : '../../icons/status_lagging.png'
            }

            Rectangle {
                color: 'transparent'
                Layout.preferredWidth: constants.paddingSmall
                height: 1
                visible: !menuButton.visible
            }

            ToolButton {
                id: menuButton
                enabled: stack.currentItem.menu !== undefined && stack.currentItem.menu.count > 0
                text: enabled ? qsTr("≡") : ''
                font.pixelSize: constants.fontSizeXLarge
                onClicked: {
                    stack.currentItem.menu.open()
                    // position the menu to the right
                    stack.currentItem.menu.x = toolbar.width - stack.currentItem.menu.width
                }
            }
        }
    }

    StackView {
        id: mainStackView
        anchors.fill: parent

        initialItem: Qt.resolvedUrl('WalletMainView.qml')
    }

    Timer {
        id: splashTimer
        interval: 10
        onTriggered: {
            splash.opacity = 0
        }
    }

    Splash {
        id: splash
        anchors.top: header.top
        anchors.bottom: app.contentItem.bottom
        width: app.width
        z: 1000

        Behavior on opacity {
            NumberAnimation { duration: 300 }
        }
    }

    property alias newWalletWizard: _newWalletWizard
    Component {
        id: _newWalletWizard
        NewWalletWizard {
            parent: Overlay.overlay
            Overlay.modal: Rectangle {
                color: "#aa000000"
            }
        }
    }

    property alias serverConnectWizard: _serverConnectWizard
    Component {
        id: _serverConnectWizard
        ServerConnectWizard {
            parent: Overlay.overlay
            Overlay.modal: Rectangle {
                color: "#aa000000"
            }
        }
    }

    property alias messageDialog: _messageDialog
    Component {
        id: _messageDialog
        Dialog {
            id: dialog
            title: qsTr("Message")

            property bool yesno: false
            property alias text: message.text

            signal yesClicked
            signal noClicked

            parent: Overlay.overlay
            modal: true
            x: (parent.width - width) / 2
            y: (parent.height - height) / 2
            Overlay.modal: Rectangle {
                color: "#aa000000"
            }

            ColumnLayout {
                TextArea {
                    id: message
                    Layout.preferredWidth: Overlay.overlay.width *2/3
                    readOnly: true
                    wrapMode: TextInput.WordWrap
                    //textFormat: TextEdit.RichText // existing translations not richtext yet
                    background: Rectangle {
                        color: 'transparent'
                    }
                }

                RowLayout {
                    Layout.alignment: Qt.AlignHCenter
                    Button {
                        text: qsTr('Ok')
                        visible: !yesno
                        onClicked: dialog.close()
                    }
                    Button {
                        text: qsTr('Yes')
                        visible: yesno
                        onClicked: {
                            yesClicked()
                            dialog.close()
                        }
                    }
                    Button {
                        text: qsTr('No')
                        visible: yesno
                        onClicked: {
                            noClicked()
                            dialog.close()
                        }
                    }
                }
            }
        }
    }

    Component.onCompleted: {
        splashTimer.start()

        if (!Config.autoConnectDefined) {
            var dialog = serverConnectWizard.createObject(app)
            // without completed serverConnectWizard we can't start
            dialog.rejected.connect(function() {
                app.visible = false
                Qt.callLater(Qt.quit)
            })
            dialog.open()
        } else {
            Daemon.load_wallet()
        }
    }

    onClosing: {
        // destroy most GUI components so that we don't dump so many null reference warnings on exit
        app.header.visible = false
        mainStackView.clear()
    }

    Connections {
        target: Daemon
        function onWalletRequiresPassword() {
            console.log('wallet requires password')
            app.stack.push(Qt.resolvedUrl("OpenWallet.qml"), {"path": Daemon.path})
        }
        function onWalletOpenError(error) {
            console.log('wallet open error')
            var dialog = app.messageDialog.createObject(app, {'text': error})
            dialog.open()
        }
    }
}
