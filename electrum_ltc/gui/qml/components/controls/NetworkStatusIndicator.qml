import QtQuick 2.6

Image {
    id: root

    sourceSize.width: constants.iconSizeMedium
    sourceSize.height: constants.iconSizeMedium

    property bool connected: Network.status == 'connected'
    property bool lagging: connected && Network.isLagging
    property bool fork: connected && Network.chaintips > 1
    property bool syncing: connected && Daemon.currentWallet && Daemon.currentWallet.synchronizing
    property bool proxy: connected && Network.proxy.mode

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
                            ? proxy
                                ? '../../../icons/status_connected_proxy_fork.png'
                                : '../../../icons/status_connected_fork.png'
                            : proxy
                                ? '../../../icons/status_connected_proxy.png'
                                : '../../../icons/status_connected.png'


    states: [
        State {
            name: 'disconnected'
            when: !connected
            PropertyChanges { target: root; rotation: 0 }
            PropertyChanges { target: root; scale: 1.0 }
        },
        State {
            name: 'normal'
            when: !(syncing || fork)
            PropertyChanges { target: root; rotation: 0 }
            PropertyChanges { target: root; scale: 1.0 }
        },
        State {
            name: 'syncing'
            when: syncing
            PropertyChanges { target: spin; running: true }
            PropertyChanges { target: root; scale: 1.0 }
        },
        State {
            name: 'forked'
            when: fork
            PropertyChanges { target: root; rotation: 0 }
            PropertyChanges { target: pulse; running: true }
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

    SequentialAnimation {
        id: pulse
        loops: Animation.Infinite
        PauseAnimation { duration: 1000 }
        NumberAnimation { target: root; property: 'scale'; from: 1.0; to: 1.5; duration: 200; easing.type: Easing.InCubic }
        NumberAnimation { target: root; property: 'scale'; to: 1.0; duration: 500; easing.type: Easing.OutCubic }
        PauseAnimation { duration: 30000 }
    }
}
