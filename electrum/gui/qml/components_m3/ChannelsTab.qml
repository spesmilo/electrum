import QtQuick
import QtQuick.Layouts
import QtQuick.Controls
import QtQuick.Controls.Material

import org.electrum 1.0

import "controls"

// Channels tab: placeholder until the Material 3 channels screen. The classic Channels.qml opens
// full screen (embedded in the tab it would bring its own heading and a second bottom button row
// above the navigation bar). Wallets without Lightning get a note, as the classic wallet menu
// hides Channels for them.
Item {
    id: root

    readonly property bool _lightning: Daemon.currentWallet && Daemon.currentWallet.isLightning

    ColumnLayout {
        anchors.centerIn: parent
        width: Math.min(parent.width, m3.maxContentWidth) - 2 * m3.screenMargin(parent.width)
        spacing: m3.space16

        M3Icon {
            Layout.alignment: Qt.AlignHCenter
            source: Qt.resolvedUrl('../../icons/m3/hub.png')
            size: 48
            color: m3.surfaceVariantOn
        }
        M3Text {
            Layout.fillWidth: true
            horizontalAlignment: Text.AlignHCenter
            wrapMode: Text.Wrap
            role: 'bodyLarge'
            color: m3.surfaceVariantOn
            text: root._lightning
                ? qsTranslate('Channels', 'You have %1 open channels').arg(Daemon.currentWallet.channelModel.numOpenChannels)
                : qsTr('This wallet has no Lightning')
        }
        M3Button {
            Layout.alignment: Qt.AlignHCenter
            visible: root._lightning
            variant: 'tonal'
            text: qsTranslate('Channels', 'Lightning Channels')
            onClicked: app.stack.pushOnRoot(Qt.resolvedUrl('../components/Channels.qml'))
        }
    }
}
