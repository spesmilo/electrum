import QtQuick 2.6
import QtQuick.Controls 2.0
import QtQuick.Layouts 1.0
import QtQuick.Controls.Material 2.0

ItemDelegate {
    id: root
    height: item.height
    width: ListView.view.width

    font.pixelSize: constants.fontSizeSmall // set default font size for child controls

    GridLayout {
        id: item

        anchors {
            left: parent.left
            right: parent.right
            leftMargin: constants.paddingSmall
            rightMargin: constants.paddingSmall
        }

        columns: 2

        Rectangle {
            Layout.columnSpan: 2
            Layout.fillWidth: true
            Layout.preferredHeight: constants.paddingTiny
            color: 'transparent'
        }

        Image {
            Layout.rowSpan: 2
            Layout.preferredWidth: constants.iconSizeLarge
            Layout.preferredHeight: constants.iconSizeLarge
            source: model.type == 0 ? "../../../icons/bitcoin.png" : "../../../icons/lightning.png"
        }

        RowLayout {
            Layout.fillWidth: true
            Label {
                Layout.fillWidth: true
                text: model.message ? model.message : model.address
                elide: Text.ElideRight
                wrapMode: Text.Wrap
                maximumLineCount: 2
                font.pixelSize: model.message ? constants.fontSizeMedium : constants.fontSizeSmall
            }

            Label {
                id: amount
                text: model.amount == 0 ? '' : Config.formatSats(model.amount)
                font.pixelSize: constants.fontSizeMedium
                font.family: FixedFont
            }

            Label {
                text: model.amount == 0 ? '' : Config.baseUnit
                font.pixelSize: constants.fontSizeMedium
                color: Material.accentColor
            }
        }

        RowLayout {
            Layout.fillWidth: true
            Label {
                text: model.status_str
                color: Material.accentColor
            }
            Item {
                Layout.fillWidth: true
                Layout.preferredHeight: status_icon.height
                Image {
                    id: status_icon
                    source: model.status == 0
                                ? '../../../icons/unpaid.png'
                                : model.status == 1
                                    ? '../../../icons/expired.png'
                                    : model.status == 3
                                        ? '../../../icons/confirmed.png'
                                        : model.status == 7
                                            ? '../../../icons/unconfirmed.png'
                                            : ''
                    width: constants.iconSizeSmall
                    height: constants.iconSizeSmall
                }
            }
            Label {
                id: fiatValue
                visible: Daemon.fx.enabled
                Layout.alignment: Qt.AlignRight
                text: model.amount == 0 ? '' : Daemon.fx.fiatValue(model.amount, false)
                font.family: FixedFont
                font.pixelSize: constants.fontSizeSmall
            }
            Label {
                visible: Daemon.fx.enabled
                Layout.alignment: Qt.AlignRight
                text: model.amount == 0 ? '' : Daemon.fx.fiatCurrency
                font.pixelSize: constants.fontSizeSmall
                color: Material.accentColor
            }
        }

        Rectangle {
            Layout.columnSpan: 2
            Layout.fillWidth: true
            Layout.preferredHeight: constants.paddingTiny
            color: 'transparent'
        }
    }

    Connections {
        target: Config
        function onBaseUnitChanged() {
            amount.text = model.amount == 0 ? '' : Config.formatSats(model.amount)
        }
        function onThousandsSeparatorChanged() {
            amount.text = model.amount == 0 ? '' : Config.formatSats(model.amount)
        }
    }
    Connections {
        target: Daemon.fx
        function onQuotesUpdated() {
            fiatValue.text = model.amount == 0 ? '' : Daemon.fx.fiatValue(model.amount, false)
        }
    }

}
