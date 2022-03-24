import QtQuick 2.6
import QtQuick.Layouts 1.0
import QtQuick.Controls 2.0
import QtQuick.Controls.Material 2.0

import org.electrum 1.0

Pane {
    id: rootItem

    property string title: Daemon.walletName + ' - ' + qsTr('Addresses')

    ColumnLayout {
        id: layout
        width: parent.width
        height: parent.height

        Item {
            width: parent.width
            Layout.fillHeight: true

            ListView {
                id: listview
                width: parent.width
                height: parent.height
                clip: true
                model: Daemon.currentWallet.addressModel

                section.property: 'type'
                section.criteria: ViewSection.FullString
                section.delegate: sectionDelegate

                delegate: AbstractButton {
                    id: delegate
                    width: ListView.view.width
                    height: delegateLayout.height

                    background: Rectangle {
                        color: model.held ? Qt.rgba(1,0,0,0.5) :
                            model.numtx > 0 && model.balance == 0 ? Qt.rgba(1,1,1,0.25) :
                            model.type == 'receive' ? Qt.rgba(0,1,0,0.25) :
                            Qt.rgba(1,0.93,0,0.25)
                        Rectangle {
                            height: 1
                            width: parent.width
                            anchors.top: parent.top
                            border.color: Material.accentColor
                            visible: model.index > 0
                        }
                    }

                    RowLayout {
                        id: delegateLayout
                        x: constants.paddingSmall
                        spacing: constants.paddingSmall
                        width: parent.width - 2*constants.paddingSmall

                        Label {
                            font.pixelSize: constants.fontSizeLarge
                            font.family: FixedFont
                            text: model.address
                            elide: Text.ElideMiddle
                            Layout.maximumWidth: delegate.width / 3
                        }
                        Label {
                            font.pixelSize: constants.fontSizeMedium
                            text: model.label
                            elide: Text.ElideRight
                            Layout.minimumWidth: delegate.width / 3
                            Layout.fillWidth: true
                        }
                        Label {
                            font.pixelSize: constants.fontSizeMedium
                            font.family: FixedFont
                            text: model.balance
                        }
                        Label {
                            font.pixelSize: constants.fontSizeMedium
                            text: model.numtx
                        }
                    }
                }

                ScrollIndicator.vertical: ScrollIndicator { }
            }

        }
    }

    Component {
        id: sectionDelegate
        Rectangle {
            id: root
            width: ListView.view.width
            height: childrenRect.height
            color: 'transparent'

            required property string section

            GridLayout {
                Label {
                    topPadding: constants.paddingMedium
                    bottomPadding: constants.paddingMedium
                    text: root.section + ' ' + qsTr('addresses')
                    font.bold: true
                    font.pixelSize: constants.fontSizeLarge
                }
                ToolButton {

                }
            }
        }
    }

    Component.onCompleted: Daemon.currentWallet.addressModel.init_model()
}
