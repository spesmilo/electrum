import QtQuick
import QtQuick.Layouts
import QtQuick.Controls

import org.electrum 1.0

// Output of a transaction (a row of a list, e.g. inside M3ListGroup): "#index", the short id, the value with
// its unit; below the address in the fixed font with "(mine)" / "(reserve)" / "(accounting)" / "(swap)" /
// "(billing)"; on the right the optional share button.
// repeats: components/controls/TxOutput.qml:8-118 (model, allowShare, allowClickAddress, idx, the
// suffix, the address color by kind, the tap on an address of this wallet, the share dialog of the address).
// Differences: Material 3 look; the tap opens the route app.routes.addressDetails instead of
// the classic file URL; colors of the address kinds are Material 3 roles (mine: success, change: tertiary,
// billing and swap: primary, accounting: secondary) instead of the classic constants.
// Strings keep the translation context of the classic file (qsTranslate('TxOutput', ...)).
Item {
    id: root

    property variant model
    property bool allowShare: true
    property bool allowClickAddress: true
    property int idx: -1

    property string _suffix: model.is_mine || model.is_change || model.is_accounting
            ? model.is_reserve
                ? qsTranslate('TxOutput', 'reserve')
                : model.is_accounting
                    ? qsTranslate('TxOutput', 'accounting')
                    : qsTranslate('TxOutput', 'mine')
            : model.is_swap
                ? qsTranslate('TxOutput', 'swap')
                : model.is_billing
                    ? qsTranslate('TxOutput', 'billing')
                    : ""

    readonly property color _addressColor: model.is_mine
        ? model.is_change
            ? m3.tertiary
            : m3.success
        : model.is_billing
            ? m3.primary
            : model.is_swap
                ? m3.primary
                : model.is_accounting
                    ? m3.secondary
                    : m3.surfaceOn

    Layout.fillWidth: true
    implicitHeight: row.implicitHeight + 2 * m3.space12

    RowLayout {
        id: row
        anchors.left: parent.left
        anchors.right: parent.right
        anchors.leftMargin: m3.space16
        anchors.rightMargin: root.allowShare ? m3.space4 : m3.space16
        anchors.verticalCenter: parent.verticalCenter
        spacing: m3.space8

        ColumnLayout {
            Layout.fillWidth: true
            spacing: m3.space4

            RowLayout {
                Layout.fillWidth: true
                spacing: m3.space8

                M3Text {
                    visible: root.idx >= 0
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
                    color: m3.surfaceVariantOn
                    text: root.model.short_id
                }
                M3Text {
                    role: 'bodyMedium'
                    font.family: FixedFont
                    text: Config.formatSats(root.model.value)
                }
                M3Text {
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
                color: root._addressColor
                text: root.model.address + (root._suffix ? ' (' + root._suffix + ')' : '')
                TapHandler {
                    enabled: root.allowClickAddress && root.model.is_mine
                    onTapped: {
                        app.pushPage(app.routes.addressDetails, {
                            address: root.model.address
                        })
                    }
                }
            }
        }

        M3IconButton {
            Layout.alignment: Qt.AlignVCenter
            visible: root.allowShare
            tooltip: qsTranslate('TxOutput', 'Tx Output')
            icon.source: Qt.resolvedUrl('../../../icons/m3/share.png')
            onClicked: {
                var dialog = app.genericShareDialog.createObject(app, {
                    title: qsTranslate('TxOutput', 'Tx Output'),
                    text: root.model.address
                })
                dialog.open()
            }
        }
    }
}
