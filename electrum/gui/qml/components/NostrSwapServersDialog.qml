import QtQuick
import QtQuick.Layouts
import QtQuick.Controls
import QtQuick.Controls.Material

import org.electrum 1.0

import "controls"

ElDialog {
    id: dialog
    title: qsTr("Select Swap Server")

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
                                Layout.rowSpan: 3
                                source: Qt.resolvedUrl('../../icons/network.png')
                            }
                            Label {
                                text: qsTr('npub')
                                color: Material.accentColor
                            }
                            Label {
                                Layout.fillWidth: true
                                text: model.npub.substring(0,10)
                                wrapMode: Text.Wrap
                            }
                            Label {
                                text: qsTr('fee')
                                color: Material.accentColor
                            }
                            Label {
                                Layout.fillWidth: true
                                text: model.percentage_fee + '%'
                            }
                            Label {
                                text: qsTr('last seen')
                                color: Material.accentColor
                            }
                            Label {
                                Layout.fillWidth: true
                                text: model.timestamp
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
                        text: qsTr('No swap servers found')
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
