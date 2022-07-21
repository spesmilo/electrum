import QtQuick 2.6

Image {
    id: root

    sourceSize.width: constants.iconSizeMedium
    sourceSize.height: constants.iconSizeMedium

    property bool connected: Network.status == 'connected'
    property bool lagging: connected && Network.isLagging
    property bool fork: connected && Network.chaintips > 1
    property bool syncing: connected && Daemon.currentWallet && Daemon.currentWallet.synchronizing

    // ?: in order to keep this a binding..
    source: !connected
                ? '../../../icons/status_disconnected.png'
                : syncing
                    ? '../../../icons/status_waiting.png'
                    : lagging
                        ? fork
                            ? '../../../icons/status_lagging_fork.png'
                            : '../../../icons/status_lagging.png'
                        : fork
                            ? '../../../icons/status_connected_fork.png'
                            : '../../../icons/status_connected.png'

    states: [
        State {
            name: 'disconnected'
            when: !connected
            PropertyChanges { target: root; rotation: 0 }
        },
        State {
            name: 'normal'
            when: !(syncing || fork)
            PropertyChanges { target: root; rotation: 0 }
        },
        State {
            name: 'syncing'
            when: syncing
            PropertyChanges { target: spin; running: true }
        },
        State {
            name: 'forked'
            when: fork
            PropertyChanges { target: root; rotation: 0 }
        }
    ]

    RotationAnimation {
        id: spin
        target: root
        from: 0
        to: 360
        duration: 1000
        loops: Animation.Infinite
    }
}
