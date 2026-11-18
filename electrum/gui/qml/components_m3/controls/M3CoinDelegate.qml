import QtQuick
import QtQuick.Layouts
import QtQuick.Controls

import org.electrum 1.0

// One coin (UTXO) row of the Material 3 address list (AddressesPage), a delegate of a view over
// Daemon.currentWallet.addressCoinModel.filterModel: reads the roles of qeaddresslistmodel.py through the context
// property `model`, as the classic delegate does.
// repeats: components/controls/CoinDelegate.qml:7-97: `indent` (coins under their address), the state
// (frozen or not), the outpoint (fixed font, elided in the middle), the unconfirmed mark when the coin has no
// short id, the amount in the base unit when not zero, the label when there is one; `highlighted` (the row is
// selected) set by the list.
// The look is Material 3: the state is a 40 dp avatar, frozen primaryContainer with the ac_unit glyph, otherwise
// successContainer with the link glyph (on-chain coin), in place of the classic colored square; the unconfirmed
// mark is the sync glyph (as unconfirmed rows of M3HistoryDelegate). A selected row is filled with
// secondaryContainer; `tint` is the fill of a row that is not selected (the list shades coins under addresses).
ItemDelegate {
    id: delegate

    property int indent: 0
    property color tint: 'transparent'

    readonly property bool _held: model.held

    width: ListView.view ? ListView.view.width : implicitWidth
    implicitHeight: Math.max(model.label ? 72 : 56, layout.implicitHeight + 2 * m3.space8)
    leftPadding: m3.space16 + indent
    rightPadding: m3.space16
    topPadding: m3.space8
    bottomPadding: m3.space8

    background: Rectangle {
        color: delegate.highlighted
            ? (delegate.down ? m3.stateLayer(m3.secondaryContainer, m3.secondaryContainerOn, m3.statePressed)
                             : m3.secondaryContainer)
            : delegate.down
                ? m3.stateLayer(delegate.tint.a > 0 ? delegate.tint : m3.surface, m3.surfaceOn, m3.statePressed)
                : delegate.hovered || delegate.visualFocus
                    ? m3.stateLayer(delegate.tint.a > 0 ? delegate.tint : m3.surface, m3.surfaceOn, m3.stateHover)
                    : delegate.tint
    }

    contentItem: RowLayout {
        id: layout
        spacing: m3.space16

        Rectangle {
            Layout.alignment: Qt.AlignVCenter
            implicitWidth: 40
            implicitHeight: 40
            radius: 20
            color: delegate._held ? m3.primaryContainer : m3.successContainer

            M3Icon {
                anchors.centerIn: parent
                size: 24
                source: delegate._held
                    ? Qt.resolvedUrl('../../../icons/m3/ac_unit.png')
                    : Qt.resolvedUrl('../../../icons/m3/link.png')
                color: delegate._held ? m3.primaryContainerOn : m3.successContainerOn
            }
        }

        ColumnLayout {
            Layout.fillWidth: true
            Layout.alignment: Qt.AlignVCenter
            spacing: 0

            RowLayout {
                Layout.fillWidth: true
                spacing: m3.space8

                M3Text {
                    Layout.fillWidth: true
                    role: 'bodyLarge'
                    font.family: FixedFont
                    elide: Text.ElideMiddle
                    text: model.outpoint
                }
                M3Icon {
                    Layout.alignment: Qt.AlignVCenter
                    visible: !model.short_id
                    size: 18
                    source: Qt.resolvedUrl('../../../icons/m3/sync.png')
                    color: m3.surfaceVariantOn
                }
                M3Text {
                    Layout.alignment: Qt.AlignVCenter
                    visible: model.amount.satsInt != 0
                    role: 'labelLarge'
                    text: Config.formatSats(model.amount, false) + ' ' + Config.baseUnit
                }
            }

            M3Text {
                Layout.fillWidth: true
                visible: model.label
                role: 'bodyMedium'
                color: m3.surfaceVariantOn
                elide: Text.ElideRight
                maximumLineCount: 2
                wrapMode: Text.WordWrap
                lineHeightMode: Text.ProportionalHeight
                lineHeight: 1.0
                text: model.label
            }
        }
    }
}
