import QtQuick 2.6
import QtQuick.Controls 2.0
import QtQuick.Layouts 1.0
import QtQuick.Controls.Material 2.0

import org.electrum 1.0

ItemDelegate {
    id: delegate
    width: ListView.view.width
    height: delegateLayout.height
    highlighted: ListView.isCurrentItem

    font.pixelSize: constants.fontSizeMedium // set default font size for child controls

    ColumnLayout {
        id: delegateLayout
        width: parent.width
        spacing: 0

        GridLayout {
            columns: 3
            Layout.topMargin: constants.paddingSmall
            Layout.leftMargin: constants.paddingLarge + 2*constants.paddingLarge
            Layout.rightMargin: constants.paddingLarge

            Rectangle {
                id: useIndicator
                Layout.rowSpan: 2
                Layout.preferredWidth: constants.iconSizeSmall
                Layout.preferredHeight: constants.iconSizeSmall
                Layout.alignment: Qt.AlignTop
                color: model.held
                        ? constants.colorAddressFrozen
                        : constants.colorAddressUsedWithBalance
            }

            RowLayout {
                Layout.fillWidth: true
                Label {
                    font.family: FixedFont
                    text: model.outpoint
                    elide: Text.ElideMiddle
                    Layout.preferredWidth: implicitWidth + constants.paddingMedium
                }
                Label {
                    Layout.fillWidth: true
                    visible: model.short_id
                    font.family: FixedFont
                    font.pixelSize: constants.fontSizeSmall
                    text: '[' + model.short_id + ']'
                }
                Item {
                    Layout.fillWidth: true
                    Layout.alignment: Qt.AlignLeft | Qt.AlignTop
                    visible: !model.short_id
                    Image {
                        source: Qt.resolvedUrl('../../../icons/unconfirmed.png')
                        sourceSize.width: constants.iconSizeSmall
                        sourceSize.height: constants.iconSizeSmall
                    }
                }
            }

            RowLayout {
                Label {
                    font.family: FixedFont
                    text: Config.formatSats(model.amount, false)
                    visible: model.amount.satsInt != 0
                }
                Label {
                    color: Material.accentColor
                    text: Config.baseUnit
                    visible: model.amount.satsInt != 0
                }
            }

            Label {
                id: labelLabel
                Layout.fillWidth: true
                Layout.columnSpan: 2
                visible: model.label
                font.pixelSize: constants.fontSizeMedium
                text: model.label
                elide: Text.ElideRight
                maximumLineCount: 2
                wrapMode: Text.WordWrap
            }

        }

        Item {
            Layout.preferredWidth: 1
            Layout.preferredHeight: constants.paddingSmall
        }
    }
}
