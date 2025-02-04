import QtQuick
import QtQuick.Layouts
import QtQuick.Controls
import QtQuick.Controls.Material

import org.electrum 1.0

TextHighlightPane {
    id: root

    property variant model
    property int idx: -1

    property string _suffix: model.is_mine || model.is_change
            ? qsTr('mine')
            : model.is_swap
                ? qsTr('swap')
                : ""

    ColumnLayout {
        width: parent.width

        RowLayout {
            Layout.fillWidth: true
            Label {
                Layout.rightMargin: constants.paddingMedium
                text: '#' + idx
                font.family: FixedFont
                font.bold: true
            }
            Label {
                Layout.fillWidth: true
                text: model.short_id
                font.family: FixedFont
            }
            Label {
                id: txin_value
                text: model.value != undefined
                    ? Config.formatSats(model.value)
                    : '&lt;' + qsTr('unknown amount') + '&gt;'
                font.pixelSize: constants.fontSizeMedium
                font.family: FixedFont
            }
            Label {
                text: Config.baseUnit
                visible: model.value != undefined
                font.pixelSize: constants.fontSizeMedium
                color: Material.accentColor
            }
        }

        Rectangle {
            Layout.fillWidth: true
            Layout.preferredHeight: 1
            antialiasing: true
            color: constants.mutedForeground
        }

        RowLayout {
            Layout.fillWidth: true
            Label {
                Layout.fillWidth: true
                text: model.address
                    ? model.address + (_suffix
                        ? ' <span style="font-size:' + constants.fontSizeXSmall + 'px">(' + _suffix + ')</span>'
                        : "")
                    : '&lt;' + qsTr('address unknown') + '&gt;'
                font.family: FixedFont
                font.pixelSize: constants.fontSizeMedium
                textFormat: Text.RichText
                color: model.is_mine
                    ? model.is_change
                        ? constants.colorAddressInternal
                        : constants.colorAddressExternal
                    : model.is_swap
                        ? constants.colorAddressSwap
                        : Material.foreground
                wrapMode: Text.WrapAnywhere
            }
        }

    }
}

