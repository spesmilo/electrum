import QtQuick 2.6
import QtQuick.Layouts 1.0
import QtQuick.Controls 2.14
import QtQuick.Controls.Material 2.0

import org.electrum 1.0

//import "controls"

Item {
    width: parent.width
    height: rootLayout.height

    property QtObject plugin

    RowLayout {
        id: rootLayout
        Button {
            text: 'Force upload'
            enabled: !plugin.busy
            onClicked: plugin.upload()
        }
        Button {
            text: 'Force download'
            enabled: !plugin.busy
            onClicked: plugin.download()
        }
    }

    Connections {
        target: plugin
        function onUploadSuccess() {
            console.log('upload success')
        }
        function onUploadFailed() {
            console.log('upload failed')
        }
        function onDownloadSuccess() {
            console.log('download success')
        }
        function onDownloadFailed() {
            console.log('download failed')
        }
    }
}
