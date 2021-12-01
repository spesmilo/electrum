import QtQuick 2.6
import QtQuick.Controls 2.15
import QtQuick.Layouts 1.0
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
            Item {
                width: column.width
                height: column.height
                MouseArea {
                    anchors.fill: parent
                    onClicked: {
                        var dialog = app.messageDialog.createObject(app, {'message':
                            'Electrum is currently on ' + Network.networkName + ''
                        })
                        dialog.open()
                    }

                }

                Column {
                    id: column
                    visible: Network.isTestNet
                    Image {
                        anchors.horizontalCenter: parent.horizontalCenter
                        width: 16
                        height: 16
                        source: "../../icons/info.png"
                    }

                    Label {
                        id: networkNameLabel
                        text: Network.networkName
                        color: Material.accentColor
                        font.pointSize: 5
                    }
                }
            }

            Label {
                text: stack.currentItem.title
                elide: Label.ElideRight
                horizontalAlignment: Qt.AlignHCenter
                verticalAlignment: Qt.AlignVCenter
                Layout.fillWidth: true
                font.pointSize: 10
                font.bold: true
            }
            ToolButton {
                text: qsTr("⋮")
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
            x: 12
            y: 12
            width: parent.width - 24
            height: parent.height - 24

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
            x: 12
            y: 12
            width: parent.width - 24
            height: parent.height - 24

            Overlay.modal: Rectangle {
                color: "#aa000000"
            }
        }
    }

    property alias messageDialog: _messageDialog
    Component {
        id: _messageDialog
        Dialog {
            parent: Overlay.overlay
            modal: true
            x: (parent.width - width) / 2
            y: (parent.height - height) / 2

            title: "Message"
            property alias message: messageLabel.text
            Label {
                id: messageLabel
                text: "Lorem ipsum dolor sit amet..."
            }

        }
    }

    Component.onCompleted: {
        //Daemon.load_wallet()
        splashTimer.start()
        if (!Config.autoConnectDefined) {
            var dialog = serverConnectWizard.createObject(app)
            // without completed serverConnectWizard we can't start
            dialog.rejected.connect(function() {
                app.visible = false
                Qt.callLater(Qt.quit)
            })
            dialog.open()
        }
    }

    onClosing: {
        // destroy most GUI components so that we don't dump so many null reference warnings on exit
        app.header.visible = false
        mainStackView.clear()
    }
}
