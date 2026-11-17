import QtQuick
import QtQuick.Layouts
import QtQuick.Controls

import org.electrum 1.0

// Input of a transaction (a row of a list, e.g. inside M3ListGroup): "#index", the outpoint (short id), the
// value with its unit; below the address in the fixed font with "(mine)" / "(swap)" / "(accounting)".
// repeats: components/controls/TxInput.qml:8-105 @ e6df7e1c8 (model, allowClick, idx, the suffix, the value or
// "<unknown amount>", the address or "<address unknown>", its color by kind, the taps: the outpoint opens the
// previous transaction, an address of this wallet opens its details).
// Differences: Material 3 look; the taps open the routes app.routes.txDetails / app.routes.addressDetails
// (M2-MAP 4.1, G3) instead of the classic file URLs; colors of the address kinds are Material 3 roles
// (mine: success, change: tertiary, swap: primary, accounting: secondary) instead of the classic constants.
// Strings keep the translation context of the classic file (qsTranslate('TxInput', ...)).
Item {
    id: root

    property variant model
    property bool allowClick: true
    property int idx: -1

    property string _suffix: model.is_mine || model.is_change
            ? qsTranslate('TxInput', 'mine')
            : model.is_swap
                ? qsTranslate('TxInput', 'swap')
                : model.is_accounting
                    ? qsTranslate('TxInput', 'accounting')
                    : ""

    readonly property color _addressColor: model.is_mine
        ? model.is_change
            ? m3.tertiary
            : m3.success
        : model.is_swap
            ? m3.primary
            : model.is_accounting
                ? m3.secondary
                : m3.surfaceOn

    Layout.fillWidth: true
    implicitHeight: layout.implicitHeight + 2 * m3.space12

    ColumnLayout {
        id: layout
        anchors.left: parent.left
        anchors.right: parent.right
        anchors.leftMargin: m3.space16
        anchors.rightMargin: m3.space16
        anchors.verticalCenter: parent.verticalCenter
        spacing: m3.space4

        RowLayout {
            Layout.fillWidth: true
            spacing: m3.space8

            M3Text {
                role: 'labelLarge'
                font.family: FixedFont
                color: m3.surfaceVariantOn
                text: '#' + root.idx
            }
            M3Text {
                Layout.fillWidth: true
                role: 'bodyMedium'
                font.family: FixedFont
                elide: Text.ElideMiddle
                color: outpointTap.enabled ? m3.primary : m3.surfaceVariantOn
                text: root.model.short_id
                TapHandler {
                    id: outpointTap
                    enabled: root.allowClick && Boolean(root.model.prevout_txid) // only set if we have tx
                    onTapped: {
                        app.pushPage(app.routes.txDetails, {
                            txid: root.model.prevout_txid
                        })
                    }
                }
            }
            M3Text {
                role: 'bodyMedium'
                font.family: FixedFont
                text: root.model.value != undefined
                    ? Config.formatSats(root.model.value)
                    : '<' + qsTranslate('TxInput', 'unknown amount') + '>'
            }
            M3Text {
                visible: root.model.value != undefined
                role: 'bodyMedium'
                color: m3.surfaceVariantOn
                text: Config.baseUnit
            }
        }

        M3Text {
            Layout.fillWidth: true
            role: 'bodyMedium'
            font.family: FixedFont
            wrapMode: Text.WrapAnywhere
            lineHeightMode: Text.ProportionalHeight
            lineHeight: 1.0
            color: root.model.address ? root._addressColor : m3.surfaceVariantOn
            text: root.model.address
                ? root.model.address + (root._suffix ? ' (' + root._suffix + ')' : '')
                : '<' + qsTranslate('TxInput', 'address unknown') + '>'
            TapHandler {
                enabled: root.allowClick && root.model.is_mine
                onTapped: {
                    app.pushPage(app.routes.addressDetails, {
                        address: root.model.address
                    })
                }
            }
        }
    }
}
