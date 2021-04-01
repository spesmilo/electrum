import QtQuick 2.6
import QtMultimedia 5.6


Item {
    Column {
        width: parent.width

        Item {
            id: voc
            width: parent.width
            height: parent.width

            VideoOutput {
                id: vo
                anchors.fill: parent
                source: camera
                //fillMode: VideoOutput.PreserveAspectCrop
            }

            MouseArea {
                anchors.fill: parent
                onClicked: {
                    vo.grabToImage(function(result) {
                        console.log("grab: image=" + (result.image !== undefined) + " url=" + result.url)
                        if (result.image !== undefined) {
                            console.log('scanning image for QR')
                            QR.scanImage(result.image)
                        }
                    })
                }
            }
        }

        EButton {
            text: 'Exit'
            onClicked: app.stack.pop()
        }
    }

    Camera {
        id: camera
        deviceId: QtMultimedia.defaultCamera.deviceId
        viewfinder.resolution: "640x480"

        function dumpstats() {
            console.log(camera.viewfinder.resolution)
            console.log(camera.viewfinder.minimumFrameRate)
            console.log(camera.viewfinder.maximumFrameRate)
            var resolutions = camera.supportedViewfinderResolutions()
            resolutions.forEach(function(item, i) {
                console.log('' + item.width + 'x' + item.height)
            })
        }
    }


}
