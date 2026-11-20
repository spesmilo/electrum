import QtQuick
import QtQuick.Layouts
import QtQuick.Controls
import QtQuick.Controls.Material

import org.electrum 1.0

import "controls"

Pane {
    objectName: 'About'

    property string title: qsTr("About Electrum")

    Flickable {
        anchors.fill: parent
        contentHeight: rootLayout.height
        interactive: height < contentHeight

        GridLayout {
            id: rootLayout
            columns: 2
            width: parent.width

            Item {
                Layout.columnSpan: 2
                Layout.alignment: Qt.AlignHCenter
                Layout.preferredWidth: parent.width
                Layout.preferredHeight: parent.width * 3/4 // reduce height, empty space in png

                Image {
                    id: electrum_logo
                    width: parent.width
                    height: width
                    source: '../../icons/electrum_presplash.png'
                }
            }

            Label {
                text: qsTr('Version')
                Layout.alignment: Qt.AlignRight
            }
            Label {
                text: BUILD.electrum_version
            }
            Label {
                text: qsTr('License')
                Layout.alignment: Qt.AlignRight
            }
            Label {
                text: qsTr('MIT License')
            }
            Label {
                text: qsTr('Homepage')
                Layout.alignment: Qt.AlignRight
            }
            Label {
                text: '<a href="https://electrum.org">https://electrum.org</a>'
                textFormat: Text.RichText
                onLinkActivated: Qt.openUrlExternally(link)
            }
            Label {
                text: qsTr('Developers')
                Layout.alignment: Qt.AlignRight
            }
            Label {
                text: 'Thomas Voegtlin\nSomberNight\nSander van Grieken\nFelix B.'
            }
            Item {
                width: 1
                height: constants.paddingXLarge
                Layout.columnSpan: 2
            }
            Label {
                text: qsTr('Distributed by Electrum Technologies GmbH')
                Layout.columnSpan: 2
                Layout.alignment: Qt.AlignHCenter
            }

            Button {
                id: technicalDetailsButton
                property bool expanded: false
                Layout.columnSpan: 2
                Layout.alignment: Qt.AlignHCenter
                text: expanded ? qsTr('Hide technical details') : qsTr('Show technical details')
                onClicked: expanded = !expanded
            }

            Loader {
                Layout.columnSpan: 2
                Layout.fillWidth: true
                active: technicalDetailsButton.expanded
                visible: active

                sourceComponent: TextHighlightPane {
                    VersionInfo {
                        id: versionInfo
                    }

                    ColumnLayout {
                        width: parent.width
                        BusyIndicator {
                            Layout.alignment: Qt.AlignHCenter
                            visible: !versionInfo.text
                        }
                        Label {
                            Layout.fillWidth: true
                            visible: versionInfo.text
                            text: versionInfo.text
                            textFormat: Text.PlainText
                            font.family: FixedFont
                            font.pixelSize: constants.fontSizeSmall
                            wrapMode: Text.Wrap
                        }
                    }
                }
            }
        }
    }
}
