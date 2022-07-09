import QtQuick 2.6
import QtQuick.Layouts 1.0
import QtQuick.Controls 2.0
import QtQuick.Controls.Material 2.0

import org.electrum 1.0

Pane {
    id: rootItem
    padding: 0
    width: parent.width
    property string title: Daemon.currentWallet.name + ' - ' + qsTr('Addresses')

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
                currentIndex: -1

                section.property: 'type'
                section.criteria: ViewSection.FullString
                section.delegate: sectionDelegate

                delegate: ItemDelegate {
                    id: delegate
                    width: ListView.view.width
                    height: delegateLayout.height
                    highlighted: ListView.isCurrentItem

                    font.pixelSize: constants.fontSizeMedium // set default font size for child controls

                    onClicked: {
                        var page = app.stack.push(Qt.resolvedUrl('AddressDetails.qml'), {'address': model.address})
                        page.addressDetailsChanged.connect(function() {
                            // update listmodel when details change
                            listview.model.update_address(model.address)
                        })
                    }

                    ColumnLayout {
                        id: delegateLayout
                        spacing: 0
                        x: constants.paddingMedium
                        width: parent.width - 2*constants.paddingMedium

                        Item {
                            Layout.preferredWidth: 1
                            Layout.preferredHeight: constants.paddingTiny
                        }

                        GridLayout {
                            columns: 2
                            Label {
                                id: indexLabel
                                font.bold: true
                                text: '#' + ('00'+model.iaddr).slice(-2)
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
                                        ? Qt.rgba(1,0,0,0.75)
                                        : model.numtx > 0
                                            ? model.balance.satsInt == 0
                                                ? Qt.rgba(0.5,0.5,0.5,1)
                                                : Qt.rgba(0.75,0.75,0.75,1)
                                            : model.type == 'receive'
                                                ? Qt.rgba(0,1,0,0.5)
                                                : Qt.rgba(1,0.93,0,0.75)
                            }

                            RowLayout {
                                Label {
                                    id: labelLabel
                                    font.pixelSize: model.label != '' ? constants.fontSizeLarge : constants.fontSizeSmall
                                    text: model.label != '' ? model.label : '<no label>'
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

            RowLayout {
                x: constants.paddingMedium
                width: parent.width - 2 * constants.paddingMedium

                Rectangle {
                    Layout.preferredHeight: 1
                    Layout.fillWidth: true
                    color: Material.accentColor
                }
                Label {
                    padding: constants.paddingMedium
                    text: root.section + ' ' + qsTr('addresses')
                    font.bold: true
                    font.pixelSize: constants.fontSizeMedium
                }
                Rectangle {
                    Layout.preferredHeight: 1
                    Layout.fillWidth: true
                    color: Material.accentColor
                }
            }
        }
    }

}
