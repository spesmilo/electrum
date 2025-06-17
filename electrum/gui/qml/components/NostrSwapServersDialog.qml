import QtQuick
import QtQuick.Layouts
import QtQuick.Controls
import QtQuick.Controls.Material

import org.electrum 1.0

import "controls"

ElDialog {
    id: dialog
    title: qsTr("Select Swap Provider")

    property QtObject swaphelper

    property string selectedPubkey

    anchors.centerIn: parent

    padding: 0

    width: parent.width * 4/5
    height: parent.height * 4/5

    ColumnLayout {
        id: rootLayout
        width: parent.width
        height: parent.height

        Frame {
            id: accountsFrame
            Layout.fillWidth: true
            Layout.fillHeight: true
            Layout.topMargin: constants.paddingLarge
            Layout.bottomMargin: constants.paddingLarge
            Layout.leftMargin: constants.paddingMedium
            Layout.rightMargin: constants.paddingMedium

            verticalPadding: 0
            horizontalPadding: 0
            background: PaneInsetBackground {}

            ColumnLayout {
                spacing: 0
                anchors.fill: parent

                ListView {
                    id: listview
                    Layout.preferredWidth: parent.width
                    Layout.fillHeight: true
                    clip: true
                    model: swaphelper.availableSwapServers

                    Connections {
                        target: swaphelper
                        function onOffersUpdated() {
                            if (dialog.selectedPubkey) {
                                listview.currentIndex = swaphelper.availableSwapServers.indexFor(dialog.selectedPubkey)
                            }
                            console.log("swapserver list refreshed")
                        }
                    }

                    delegate: ItemDelegate {
                        width: ListView.view.width
                        height: itemLayout.height

                        onClicked: {
                            dialog.selectedPubkey = model.npub
                            dialog.doAccept()
                        }

                        GridLayout {
                            id: itemLayout
                            columns: 3
                            rowSpacing: 0

                            anchors {
                                left: parent.left
                                right: parent.right
                                leftMargin: constants.paddingMedium
                                rightMargin: constants.paddingMedium
                            }

                            Item {
                                Layout.columnSpan: 3
                                Layout.preferredHeight: constants.paddingLarge
                                Layout.preferredWidth: 1
                            }
                            Image {
                                Layout.rowSpan: 5
                                Layout.alignment: Qt.AlignTop
                                source: Qt.resolvedUrl('../../icons/network.png')
                            }
                            Label {
                                text: qsTr('Pubkey')
                                color: Material.accentColor
                            }
                            Label {
                                Layout.fillWidth: true
                                // only show the prefix of the pubkey for readability, but
                                // keep it long enough so that collisions are hard to brute-force:
                                text: model.server_pubkey.substring(0,32)
                                wrapMode: Text.Wrap
                            }
                            Label {
                                text: qsTr('Fee')
                                color: Material.accentColor
                            }
                            Label {
                                Layout.fillWidth: true
                                text: model.percentage_fee + '% + ' + model.mining_fee + ' sat'
                            }
                            Label {
                                text: qsTr('Last seen')
                                color: Material.accentColor
                            }
                            Label {
                                Layout.fillWidth: true
                                text: model.timestamp
                            }
                            Label {
                                text: qsTr('Max Forward')
                                color: Material.accentColor
                            }
                            RowLayout{
                                Layout.fillWidth: true
                                Label {
                                    text: Config.formatSats(model.max_forward_amount)
                                }
                                Label {
                                    text: Config.baseUnit
                                    color: Material.accentColor
                                }
                            }
                            Label {
                                text: qsTr('Max Reverse')
                                color: Material.accentColor
                            }
                            RowLayout{
                                Layout.fillWidth: true
                                Label {
                                    text: Config.formatSats(model.max_reverse_amount)
                                }
                                Label {
                                    text: Config.baseUnit
                                    color: Material.accentColor
                                }
                            }
                            Item {
                                Layout.columnSpan: 3
                                Layout.preferredHeight: constants.paddingLarge
                                Layout.preferredWidth: 1
                            }
                        }
                    }

                    ScrollIndicator.vertical: ScrollIndicator { }

                    Label {
                        visible: swaphelper.availableSwapServers.count == 0
                        anchors.centerIn: parent
                        width: listview.width * 4/5
                        font.pixelSize: constants.fontSizeXXLarge
                        color: constants.mutedForeground
                        text: qsTr('No swap providers found')
                        wrapMode: Text.Wrap
                        horizontalAlignment: Text.AlignHCenter
                    }

                }
            }
        }
    }

    Component.onCompleted: {
        if (dialog.selectedPubkey) {
            listview.currentIndex = swaphelper.availableSwapServers.indexFor(dialog.selectedPubkey)
        }
    }
}
