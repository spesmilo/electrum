import QtQuick
import QtQuick.Layouts
import QtQuick.Controls

import org.electrum 1.0

// One address row of the Material 3 address list (AddressesPage), a delegate of a view over
// Daemon.currentWallet.addressCoinModel.filterModel: reads the roles of qeaddresslistmodel.py through the context
// property `model`, as the classic delegate does.
// repeats: components/controls/AddressDelegate.qml:7-95 @ e6df7e1c8: the index '#NN' (two digits below 10), the
// address (fixed font, elided in the middle), the state of the address (frozen; used with or without balance;
// change or receive, unused), the label or '<no label>', the balance in the base unit and the number of
// transactions, each only when not zero; `highlighted` (the row is selected) set by the list.
// The look is Material 3: the state is a 40 dp avatar with the index (a frozen address also has a badge with the
// ac_unit glyph on the avatar), filled with a role per state in place of the classic colored square: frozen
// primaryContainer, used with balance successContainer, used and empty surfaceContainerHighest, unused change
// tertiaryContainer, unused receive secondaryContainer. A selected row is filled with secondaryContainer.
ItemDelegate {
    id: delegate

    readonly property bool _held: model.held
    readonly property bool _used: model.numtx > 0
    readonly property bool _hasBalance: model.balance.satsInt != 0
    readonly property bool _change: model.type == 'change'

    readonly property color _avatarColor: _held
        ? m3.primaryContainer
        : _used
            ? (_hasBalance ? m3.successContainer : m3.surfaceContainerHighest)
            : (_change ? m3.tertiaryContainer : m3.secondaryContainer)
    readonly property color _avatarContent: _held
        ? m3.primaryContainerOn
        : _used
            ? (_hasBalance ? m3.successContainerOn : m3.surfaceVariantOn)
            : (_change ? m3.tertiaryContainerOn : m3.secondaryContainerOn)

    width: ListView.view ? ListView.view.width : implicitWidth
    implicitHeight: Math.max(72, layout.implicitHeight + 2 * m3.space8)
    leftPadding: m3.space16
    rightPadding: m3.space16
    topPadding: m3.space8
    bottomPadding: m3.space8

    background: Rectangle {
        color: delegate.highlighted
            ? (delegate.down ? m3.stateLayer(m3.secondaryContainer, m3.secondaryContainerOn, m3.statePressed)
                             : m3.secondaryContainer)
            : delegate.down
                ? Qt.rgba(m3.surfaceOn.r, m3.surfaceOn.g, m3.surfaceOn.b, m3.statePressed)
                : delegate.hovered || delegate.visualFocus
                    ? Qt.rgba(m3.surfaceOn.r, m3.surfaceOn.g, m3.surfaceOn.b, m3.stateHover)
                    : 'transparent'
    }

    contentItem: RowLayout {
        id: layout
        spacing: m3.space16

        Rectangle {
            Layout.alignment: Qt.AlignVCenter
            implicitWidth: 40
            implicitHeight: 40
            radius: 20
            color: delegate._avatarColor

            M3Text {
                anchors.centerIn: parent
                role: 'labelMedium'
                color: delegate._avatarContent
                text: model.addridx < 10
                    ? '#' + ('0'+model.addridx).slice(-2)
                    : '#' + model.addridx
            }
            // frozen: a badge with the ac_unit glyph on the lower right of the avatar (the index stays visible);
            // the ring has the color of the row, so the badge stands apart from the avatar
            Rectangle {
                visible: delegate._held
                width: 20
                height: 20
                radius: 10
                x: parent.width - width + 4
                y: parent.height - height + 4
                color: m3.primary
                border.width: 2
                border.color: delegate.highlighted ? m3.secondaryContainer : m3.surface

                M3Icon {
                    anchors.centerIn: parent
                    size: 14
                    source: Qt.resolvedUrl('../../../icons/m3/ac_unit.png')
                    color: m3.primaryOn
                }
            }
        }

        ColumnLayout {
            Layout.fillWidth: true
            Layout.alignment: Qt.AlignVCenter
            spacing: 0

            M3Text {
                Layout.fillWidth: true
                role: 'bodyLarge'
                font.family: FixedFont
                elide: Text.ElideMiddle
                text: model.address
            }

            RowLayout {
                Layout.fillWidth: true
                spacing: m3.space8

                M3Text {
                    Layout.fillWidth: true
                    role: 'bodyMedium'
                    color: m3.surfaceVariantOn
                    font.italic: model.label == ''
                    elide: Text.ElideRight
                    maximumLineCount: 2
                    wrapMode: Text.WordWrap
                    lineHeightMode: Text.ProportionalHeight
                    lineHeight: 1.0
                    text: model.label != '' ? model.label : qsTranslate('AddressDelegate', '<no label>')
                }
                M3Text {
                    Layout.alignment: Qt.AlignTop
                    visible: delegate._hasBalance
                    role: 'labelLarge'
                    text: Config.formatSats(model.balance, false) + ' ' + Config.baseUnit
                }
                M3Text {
                    Layout.alignment: Qt.AlignTop
                    visible: delegate._used
                    role: 'bodySmall'
                    color: m3.surfaceVariantOn
                    text: model.numtx + ' ' + qsTranslate('AddressDelegate', 'tx')
                }
            }
        }
    }
}
