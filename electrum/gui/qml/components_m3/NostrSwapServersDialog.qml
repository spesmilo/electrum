import QtQuick
import QtQuick.Layouts
import QtQuick.Controls

import org.electrum 1.0

import "controls"

// "Select Swap Provider" of the Material 3 GUI: the type of the app.nostrSwapServersDialog factory (main.qml
// onUndefinedNPub of the SwapHelper, and "Choose swap provider" of SwapDialog). M2-MAP F-2: a long list -> a
// full-screen dialog.
// repeats: components/NostrSwapServersDialog.qml:10-187 @ e6df7e1c8: the API (`swaphelper`, not required;
// writable `selectedPubkey`; accepted / rejected: closing without a choice (X, Android back) rejects, so the swap
// does not wait for a provider forever); the list over swaphelper.availableSwapServers with the roles color,
// server_pubkey (its first 32 characters), percentage_fee, mining_fee, timestamp, max_forward_amount,
// max_reverse_amount; a tap sets selectedPubkey and accepts; the current row follows selectedPubkey at start and
// on offersUpdated; "No swap providers found" for an empty list.
// Look: Material 3 rows (the color strip of the server, the details as label / value pairs), the server of
// selectedPubkey marked with a tint and a check (no row while selectedPubkey is empty); the empty state centered.
// Strings keep the translation context of the classic file (qsTranslate('NostrSwapServersDialog', ...)).
M3FullScreenDialog {
    id: dialog
    title: qsTranslate('NostrSwapServersDialog', 'Select Swap Provider')

    property QtObject swaphelper

    property string selectedPubkey

    ListView {
        id: listview
        anchors.fill: parent
        clip: true
        boundsBehavior: Flickable.StopAtBounds
        topMargin: m3.space8
        bottomMargin: m3.space16
        model: swaphelper.availableSwapServers

        readonly property int _columnWidth: Math.min(width, m3.maxContentWidth) - 2 * m3.screenMargin(width)

        Connections {
            target: swaphelper
            function onOffersUpdated() {
                if (dialog.selectedPubkey) {
                    listview.currentIndex = swaphelper.availableSwapServers.indexFor(dialog.selectedPubkey)
                }
                console.log("swapserver list refreshed")
            }
        }

        delegate: Item {
            id: wrap
            width: ListView.view.width
            height: row.height

            ItemDelegate {
                id: row
                width: listview._columnWidth + 2 * m3.space16
                anchors.horizontalCenter: parent.horizontalCenter
                implicitHeight: rowLayout.implicitHeight + 2 * m3.space12
                leftPadding: m3.space16
                rightPadding: m3.space16
                topPadding: m3.space12
                bottomPadding: m3.space12

                // the selected server is the row of selectedPubkey, not the current row of the list: with nothing
                // selected the list still makes row 0 current, and it must not look chosen
                readonly property bool _current: dialog.selectedPubkey !== '' && model.npub === dialog.selectedPubkey

                onClicked: {
                    dialog.selectedPubkey = model.npub
                    dialog.doAccept()
                }

                background: Rectangle {
                    color: row.down
                        ? Qt.rgba(m3.surfaceOn.r, m3.surfaceOn.g, m3.surfaceOn.b, m3.statePressed)
                        : row.hovered || row.visualFocus
                            ? Qt.rgba(m3.surfaceOn.r, m3.surfaceOn.g, m3.surfaceOn.b, m3.stateHover)
                            : row._current ? m3.secondaryContainer : 'transparent'
                    radius: m3.radiusM
                }

                contentItem: RowLayout {
                    id: rowLayout
                    spacing: m3.space16

                    Rectangle {
                        Layout.fillHeight: true
                        Layout.preferredWidth: 8
                        radius: 4
                        color: model.color
                    }

                    GridLayout {
                        Layout.fillWidth: true
                        columns: 2
                        rowSpacing: 2
                        columnSpacing: m3.space12

                        ServerLabel { text: qsTranslate('NostrSwapServersDialog', 'Pubkey') }
                        M3Text {
                            Layout.fillWidth: true
                            role: 'bodyMedium'
                            font.family: FixedFont
                            // only show the prefix of the pubkey for readability, but
                            // keep it long enough so that collisions are hard to brute-force:
                            text: model.server_pubkey.substring(0,32)
                            wrapMode: Text.WrapAnywhere
                        }
                        ServerLabel { text: qsTranslate('NostrSwapServersDialog', 'Fee') }
                        M3Text {
                            Layout.fillWidth: true
                            role: 'bodyMedium'
                            text: model.percentage_fee + '% + ' + model.mining_fee + ' sat'
                        }
                        ServerLabel { text: qsTranslate('NostrSwapServersDialog', 'Last seen') }
                        M3Text {
                            Layout.fillWidth: true
                            role: 'bodyMedium'
                            text: model.timestamp
                            wrapMode: Text.Wrap
                        }
                        ServerLabel { text: qsTranslate('NostrSwapServersDialog', 'Max Forward') }
                        M3Text {
                            Layout.fillWidth: true
                            role: 'bodyMedium'
                            text: Config.formatSats(model.max_forward_amount) + ' ' + Config.baseUnit
                        }
                        ServerLabel { text: qsTranslate('NostrSwapServersDialog', 'Max Reverse') }
                        M3Text {
                            Layout.fillWidth: true
                            role: 'bodyMedium'
                            text: Config.formatSats(model.max_reverse_amount) + ' ' + Config.baseUnit
                        }
                    }

                    M3Icon {
                        Layout.alignment: Qt.AlignVCenter
                        visible: row._current
                        source: Qt.resolvedUrl('../../icons/m3/check.png')
                        color: m3.primary
                    }
                }
            }
        }

        ScrollIndicator.vertical: ScrollIndicator { }
    }

    // the empty list: centered in the dialog, outside the list content
    ColumnLayout {
        visible: swaphelper.availableSwapServers.count == 0
        anchors.centerIn: parent
        width: listview._columnWidth
        spacing: m3.space16

        M3Icon {
            Layout.alignment: Qt.AlignHCenter
            size: 48
            source: Qt.resolvedUrl('../../icons/m3/dns.png')
            color: m3.surfaceVariantOn
        }
        M3Text {
            Layout.fillWidth: true
            role: 'bodyLarge'
            color: m3.surfaceVariantOn
            text: qsTranslate('NostrSwapServersDialog', 'No swap providers found')
            wrapMode: Text.Wrap
            horizontalAlignment: Text.AlignHCenter
        }
    }

    Component.onCompleted: {
        if (dialog.selectedPubkey) {
            listview.currentIndex = swaphelper.availableSwapServers.indexFor(dialog.selectedPubkey)
        }
    }

    component ServerLabel: M3Text {
        role: 'bodySmall'
        color: m3.surfaceVariantOn
    }
}
