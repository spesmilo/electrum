import QtQuick 2.6
import QtQuick.Layouts 1.0
import QtQuick.Controls 2.0
import QtQuick.Controls.Material 2.0

import org.electrum 1.0

Pane {
    id: rootItem

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
                    onClicked: ListView.view.currentIndex == index
                        ? ListView.view.currentIndex = -1
                        : ListView.view.currentIndex = index

                    states: [
                        State {
                            name: 'normal'; when: !highlighted
                            PropertyChanges { target: drawer; visible: false }
                            PropertyChanges { target: labelLabel; maximumLineCount: 2 }

                        },
                        State {
                            name: 'highlighted'; when: highlighted
                            PropertyChanges { target: drawer; visible: true }
                            PropertyChanges { target: labelLabel; maximumLineCount: 4 }
                        }
                    ]


                    ColumnLayout {
                        id: delegateLayout
//                         x: constants.paddingSmall
                        spacing: 0
                        //width: parent.width - 2*constants.paddingSmall
                        width: parent.width

                        Item {
                            Layout.preferredWidth: 1
                            Layout.preferredHeight: constants.paddingTiny
                        }

                        GridLayout {
                            columns: 2
                            Label {
                                id: indexLabel
                                font.pixelSize: constants.fontSizeMedium
                                font.bold: true
                                text: '#' + ('00'+model.iaddr).slice(-2)
                                Layout.fillWidth: true
                            }
                            Label {
                                font.pixelSize: constants.fontSizeMedium
                                font.family: FixedFont
                                text: model.address
                                Layout.fillWidth: true
                            }

                            Rectangle {
                                Layout.preferredWidth: constants.iconSizeMedium
                                Layout.preferredHeight: constants.iconSizeMedium
                                color: model.held
                                        ? Qt.rgba(1,0.93,0,0.75)
                                        : model.numtx > 0 && model.balance == 0
                                            ? Qt.rgba(0.75,0.75,0.75,1)
                                            : model.type == 'receive'
                                                ? Qt.rgba(0,1,0,0.5)
                                                : Qt.rgba(1,0.93,0,0.25)
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
                                    font.pixelSize: constants.fontSizeMedium
                                    font.family: FixedFont
                                    text: Config.formatSats(model.balance, false)
                                }
                                Label {
                                    font.pixelSize: constants.fontSizeMedium
                                    color: Material.accentColor
                                    text: Config.baseUnit + ','
                                }
                                Label {
                                    font.pixelSize: constants.fontSizeMedium
                                    text: model.numtx
                                }
                                Label {
                                    font.pixelSize: constants.fontSizeMedium
                                    color: Material.accentColor
                                    text: qsTr('tx')
                                }
                            }
                        }

                        RowLayout {
                            id: drawer
                            Layout.fillWidth: true
                            Layout.preferredHeight: 50

                            ToolButton {
                                icon.source: '../../icons/qrcode.png'
                                icon.color: 'transparent'
                                icon.width: constants.iconSizeMedium
                                icon.height: constants.iconSizeMedium
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
