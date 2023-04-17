import QtQuick 2.6
import QtQuick.Layouts 1.0
import QtQuick.Controls 2.0
import QtQuick.Controls.Material 2.0

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
                text: qsTr('APK Version')
                Layout.alignment: Qt.AlignRight
            }
            Label {
                text: BUILD.apk_version
            }
            Label {
                text: qsTr('Protocol version')
                Layout.alignment: Qt.AlignRight
            }
            Label {
                text: BUILD.protocol_version
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
                text: qsTr('<a href="https://electrum.org">https://electrum.org</a>')
                textFormat: Text.RichText
                onLinkActivated: Qt.openUrlExternally(link)
            }
            Label {
                text: qsTr('Developers')
                Layout.alignment: Qt.AlignRight
            }
            Label {
                text: 'Thomas Voegtlin\nSomberNight\nSander van Grieken'
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
        }
    }

}
