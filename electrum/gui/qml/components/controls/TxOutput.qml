import QtQuick
import QtQuick.Layouts
import QtQuick.Controls
import QtQuick.Controls.Material

import org.electrum 1.0

TextHighlightPane {
    id: root

    property variant model
    property bool allowShare: true
    property bool allowClickAddress: true
    property int idx: -1

    property string _suffix: model.is_mine || model.is_change
            ? qsTr('mine')
            : model.is_swap
                ? qsTr('swap')
                : model.is_billing
                    ? qsTr('billing')
                    : ""

    RowLayout {
        width: parent.width

        ColumnLayout {
            Layout.fillWidth: true

            RowLayout {
                Layout.fillWidth: true

                Label {
                    Layout.rightMargin: constants.paddingLarge
                    text: '#' + idx
                    visible: idx >= 0
                    font.family: FixedFont
                    font.pixelSize: constants.fontSizeMedium
                    font.bold: true
                }
                Label {
                    Layout.fillWidth: true
                    font.family: FixedFont
                    text: model.short_id
                }
                Label {
                    text: Config.formatSats(model.value)
                    font.pixelSize: constants.fontSizeMedium
                    font.family: FixedFont
                }
                Label {
                    text: Config.baseUnit
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
                    text: model.address + (_suffix
                        ? ' <span style="font-size:' + constants.fontSizeXSmall + 'px">(' + _suffix + ')</span>'
                        : "")
                    Layout.fillWidth: true
                    wrapMode: Text.Wrap
                    font.pixelSize: constants.fontSizeMedium
                    font.family: FixedFont
                    textFormat: Text.RichText
                    color: model.is_mine
                        ? model.is_change
                            ? constants.colorAddressInternal
                            : constants.colorAddressExternal
                        : model.is_billing
                            ? constants.colorAddressBilling
                            : model.is_swap
                                ? constants.colorAddressSwap
                                : Material.foreground
                    TapHandler {
                        enabled: allowClickAddress && model.is_mine
                        onTapped: {
                            app.stack.push(Qt.resolvedUrl('../AddressDetails.qml'), {
                                address: model.address
                            })
                        }
                    }
                }
            }

        }

        ToolButton {
            visible: allowShare
            icon.source: Qt.resolvedUrl('../../../icons/share.png')
            icon.color: 'transparent'
            onClicked: {
                var dialog = app.genericShareDialog.createObject(app, {
                    title: qsTr('Tx Output'),
                    text: model.address
                })
                dialog.open()
            }
        }

    }
}

