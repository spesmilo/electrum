import QtQuick
import QtQuick.Controls
import QtQuick.Layouts
import QtQuick.Controls.Material

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
            columns: 2
            Layout.topMargin: constants.paddingSmall
            Layout.leftMargin: constants.paddingLarge
            Layout.rightMargin: constants.paddingLarge

            Label {
                id: indexLabel
                font.bold: true
                text: model.addridx < 10
                    ? '#' + ('0'+model.addridx).slice(-2)
                    : '#' + model.addridx
                Layout.fillWidth: true
            }
            Label {
                font.family: FixedFont
                text: model.address
                elide: Text.ElideMiddle
                Layout.fillWidth: true
            }

            Rectangle {
                id: useIndicator
                Layout.preferredWidth: constants.iconSizeMedium
                Layout.preferredHeight: constants.iconSizeMedium
                color: model.held
                        ? constants.colorAddressFrozen
                        : model.numtx > 0
                            ? model.balance.satsInt == 0
                                ? constants.colorAddressUsed
                                : constants.colorAddressUsedWithBalance
                            : model.type == 'change'
                                ? constants.colorAddressInternal
                                : constants.colorAddressExternal
            }

            RowLayout {
                Label {
                    id: labelLabel
                    font.pixelSize: model.label != '' ? constants.fontSizeLarge : constants.fontSizeSmall
                    text: model.label != '' ? model.label : qsTr('<no label>')
                    opacity: model.label != '' ? 1.0 : 0.8
                    elide: Text.ElideRight
                    maximumLineCount: 2
                    wrapMode: Text.WordWrap
                    Layout.fillWidth: true
                }
                Label {
                    font.family: FixedFont
                    text: Config.formatSats(model.balance, false)
                    visible: model.balance.satsInt != 0
                }
                Label {
                    color: Material.accentColor
                    text: Config.baseUnit + ','
                    visible: model.balance.satsInt != 0
                }
                Label {
                    text: model.numtx
                    visible: model.numtx > 0
                }
                Label {
                    color: Material.accentColor
                    text: qsTr('tx')
                    visible: model.numtx > 0
                }
            }
        }

        Item {
            Layout.preferredWidth: 1
            Layout.preferredHeight: constants.paddingSmall
        }
    }
}
