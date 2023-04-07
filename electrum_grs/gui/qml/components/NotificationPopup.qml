import QtQuick 2.6
import QtQuick.Layouts 1.0
import QtQuick.Controls 2.3
import QtQuick.Controls.Material 2.0
import QtQuick.Controls.Material.impl 2.12

Item {
    id: root

    property string message
    property string wallet_name
    property bool _hide: true

    clip:true

    layer.enabled: height > 0
    layer.effect: ElevationEffect {
        elevation: constants.paddingXLarge
        fullWidth: true
    }

    states: [
        State {
            name: 'expanded'; when: !_hide
            PropertyChanges { target: root; height: layout.implicitHeight }
        }
    ]

    transitions: [
        Transition {
            from: ''; to: 'expanded'; reversible: true
            NumberAnimation { target: root; properties: 'height'; duration: 300; easing.type: Easing.OutQuad }
        }
    ]

    function show(wallet_name, message) {
        root.wallet_name = wallet_name
        root.message = message
        root._hide = false
        closetimer.start()
    }

    Rectangle {
        id: rect
        width: root.width
        height: layout.height
        color: constants.colorAlpha(Material.dialogColor, 0.8)
        anchors.bottom: root.bottom

        ColumnLayout {
            id: layout
            width: parent.width
            spacing: 0

            RowLayout {
                Layout.margins: constants.paddingLarge
                spacing: constants.paddingSmall

                Image {
                    source: '../../icons/info.png'
                    Layout.preferredWidth: constants.iconSizeLarge
                    Layout.preferredHeight: constants.iconSizeLarge
                }

                Label {
                    id: messageLabel
                    Layout.fillWidth: true
                    font.pixelSize: constants.fontSizeLarge
                    color: Material.foreground
                    wrapMode: Text.Wrap
                    text: root.message
                }
            }
            Rectangle {
                Layout.preferredHeight: 2
                Layout.fillWidth: true
                color: Material.accentColor
            }
        }

        RowLayout {
            visible: root.wallet_name && root.wallet_name != Daemon.currentWallet.name
            anchors.right: rect.right
            anchors.bottom: rect.bottom

            RowLayout {
                Layout.margins: constants.paddingSmall
                Image {
                    source: '../../icons/wallet.png'
                    Layout.preferredWidth: constants.iconSizeXSmall
                    Layout.preferredHeight: constants.iconSizeXSmall
                }

                Label {
                    font.pixelSize: constants.fontSizeSmall
                    color: Material.accentColor
                    text: root.wallet_name
                }
            }
        }
    }

    MouseArea {
        // capture all clicks
        anchors.fill: parent
    }

    Timer {
        id: closetimer
        interval: 5000
        repeat: false
        onTriggered: _hide = true
    }

}
