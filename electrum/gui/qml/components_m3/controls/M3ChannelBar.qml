import QtQuick
import QtQuick.Controls
import QtQuick.Layouts

import org.electrum 1.0

// Capacity bar of a Lightning channel in the Material 3 GUI (the channel list of the Channels tab and the
// channel details page): the left half is our side, the right half the remote side, each split into what can
// be used now (can send / can receive), the reserve, and the unused part of the capacity.
// repeats: components/controls/ChannelBar.qml:8-111 (the API: capacity, localCapacity, remoteCapacity,
// canSend, canReceive (Amount), frozenForSending, frozenForReceiving; the six segments and their widths in
// do_update(), frozen sending / receiving shows the whole side as reserve; the updates on a width change, on new
// amounts and on in-place amount changes).
// Colors (existing Material 3 roles, M3Theme unchanged): can send m3.primary, local reserve
// m3.primaryContainerOn (the classic darker blue), can receive m3.tertiary (amber, the "Lightning" role of the
// theme, the classic yellow), remote reserve m3.tertiaryContainerOn (the classic darker yellow), the unused part
// m3.outlineVariant (the classic gray). All but the unused part differ from each other and from the group
// background in both themes.
Item {
    id: root

    property var capacity  // type: Amount
    property var localCapacity  // type: Amount
    property var remoteCapacity  // type: Amount
    property var canSend  // type: Amount
    property var canReceive  // type: Amount
    property bool frozenForSending: false
    property bool frozenForReceiving: false

    readonly property color colorLocal: m3.primary
    readonly property color colorLocalReserve: m3.primaryContainerOn
    readonly property color colorRemote: m3.tertiary
    readonly property color colorRemoteReserve: m3.tertiaryContainerOn
    readonly property color colorUnused: m3.outlineVariant

    implicitHeight: 8
    implicitWidth: 100

    function update() {
        Qt.callLater(do_update)
    }

    function do_update() {
        if (!capacity || !localCapacity || !remoteCapacity || !canSend || !canReceive)
            return
        var cap = capacity.satsInt * 1000
        var twocap = cap * 2
        if (twocap <= 0)
            return
        l1.width = width * (cap - localCapacity.msatsInt) / twocap
        if (frozenForSending) {
            l2.width = width * localCapacity.msatsInt / twocap
            l3.width = 0
        } else {
            l2.width = width * (localCapacity.msatsInt - canSend.msatsInt) / twocap
            l3.width = width * canSend.msatsInt / twocap
        }
        if (frozenForReceiving) {
            r3.width = 0
            r2.width = width * remoteCapacity.msatsInt / twocap
        } else {
            r3.width = width * canReceive.msatsInt / twocap
            r2.width = width * (remoteCapacity.msatsInt - canReceive.msatsInt) / twocap
        }
        r1.width = width * (cap - remoteCapacity.msatsInt) / twocap
    }

    onWidthChanged: update()
    onFrozenForSendingChanged: update()
    onFrozenForReceivingChanged: update()
    // the channel list model replaces the amounts, the Connections below handle in-place updates
    onCapacityChanged: update()
    onLocalCapacityChanged: update()
    onRemoteCapacityChanged: update()
    onCanSendChanged: update()
    onCanReceiveChanged: update()

    Connections {
        target: root.localCapacity
        function onMsatsIntChanged() { root.update() }
    }

    Connections {
        target: root.remoteCapacity
        function onMsatsIntChanged() { root.update() }
    }

    Connections {
        target: root.canSend
        function onMsatsIntChanged() { root.update() }
    }

    Connections {
        target: root.canReceive
        function onMsatsIntChanged() { root.update() }
    }

    Rectangle {
        id: l1
        x: 0
        height: parent.height
        color: root.colorUnused
    }
    Rectangle {
        id: l2
        anchors.left: l1.right
        height: parent.height
        color: root.colorLocalReserve
    }
    Rectangle {
        id: l3
        anchors.left: l2.right
        height: parent.height
        color: root.colorLocal
    }
    Rectangle {
        id: r3
        anchors.left: l3.right
        height: parent.height
        color: root.colorRemote
    }
    Rectangle {
        id: r2
        anchors.left: r3.right
        height: parent.height
        color: root.colorRemoteReserve
    }
    Rectangle {
        id: r1
        anchors.left: r2.right
        height: parent.height
        color: root.colorUnused
    }
}
