import QtQuick 2.12
import QtQuick.Controls 2.0
import QtMultimedia 5.6

Item {
    id: scanner

    property bool active: false
    property string url
    property string scanData

    property bool _pointsVisible

    signal found

    VideoOutput {
        id: vo
        anchors.fill: parent
        source: camera
        fillMode: VideoOutput.PreserveAspectCrop

        Rectangle {
            width: parent.width
            height: (parent.height - parent.width) / 2
            anchors.top: parent.top
            color: Qt.rgba(0,0,0,0.5)
        }
        Rectangle {
            width: parent.width
            height: (parent.height - parent.width) / 2
            anchors.bottom: parent.bottom
            color: Qt.rgba(0,0,0,0.5)
        }
    }

    Image {
        id: still
        anchors.fill: vo
    }

    SequentialAnimation {
        id: foundAnimation
        PropertyAction { target: scanner; property: '_pointsVisible'; value: true}
        PauseAnimation { duration: 80 }
        PropertyAction { target: scanner; property: '_pointsVisible'; value: false}
        PauseAnimation { duration: 80 }
        PropertyAction { target: scanner; property: '_pointsVisible'; value: true}
        PauseAnimation { duration: 80 }
        PropertyAction { target: scanner; property: '_pointsVisible'; value: false}
        PauseAnimation { duration: 80 }
        PropertyAction { target: scanner; property: '_pointsVisible'; value: true}
        PauseAnimation { duration: 80 }
        PropertyAction { target: scanner; property: '_pointsVisible'; value: false}
        PauseAnimation { duration: 80 }
        PropertyAction { target: scanner; property: '_pointsVisible'; value: true}
        onFinished: found()
    }

    Component {
        id: r
        Rectangle {
            property int cx
            property int cy
            width: 15
            height: 15
            x: cx - width/2
            y: cy - height/2
            radius: 5
            visible: scanner._pointsVisible
        }
    }

    Connections {
        target: QR
        function onDataChanged() {
            console.log(QR.data)
            scanner.active = false
            scanner.scanData = QR.data
            still.source = scanner.url

            var sx = still.width/still.sourceSize.width
            var sy = still.height/still.sourceSize.height
            r.createObject(scanner, {cx: QR.points[0].x * sx, cy: QR.points[0].y * sy, color: 'yellow'})
            r.createObject(scanner, {cx: QR.points[1].x * sx, cy: QR.points[1].y * sy, color: 'yellow'})
            r.createObject(scanner, {cx: QR.points[2].x * sx, cy: QR.points[2].y * sy, color: 'yellow'})
            r.createObject(scanner, {cx: QR.points[3].x * sx, cy: QR.points[3].y * sy, color: 'yellow'})

            foundAnimation.start()
        }
    }

    Camera {
        id: camera
        deviceId: QtMultimedia.defaultCamera.deviceId
        viewfinder.resolution: "640x480"

        focus {
            focusMode: Camera.FocusContinuous
            focusPointMode: Camera.FocusPointCustom
            customFocusPoint: Qt.point(0.5, 0.5)
        }

        function dumpstats() {
            console.log(camera.viewfinder.resolution)
            console.log(camera.viewfinder.minimumFrameRate)
            console.log(camera.viewfinder.maximumFrameRate)
            var resolutions = camera.supportedViewfinderResolutions()
            resolutions.forEach(function(item, i) {
                console.log('' + item.width + 'x' + item.height)
            })
            // TODO
            // pick a suitable resolution from the available resolutions
            // problem: some cameras have no supportedViewfinderResolutions
            // but still error out when an invalid resolution is set.
            // 640x480 seems to be universally available, but this needs to
            // be checked across a range of phone models.
        }
    }

    Timer {
        id: scanTimer
        interval: 200
        repeat: true
        running: scanner.active
        onTriggered: {
            if (QR.busy)
                return
            vo.grabToImage(function(result) {
                if (result.image !== undefined) {
                    scanner.url = result.url
                    QR.scanImage(result.image)
                } else {
                    console.log('image grab returned null')
                }
            })
        }
    }

    Component.onCompleted: {
        console.log('Scan page initialized')
        QtMultimedia.availableCameras.forEach(function(item) {
            console.log('cam found')
            console.log(item.deviceId)
            console.log(item.displayName)
            console.log(item.position)
            console.log(item.orientation)
            if (QtMultimedia.defaultCamera.deviceId == item.deviceId) {
                vo.orientation = item.orientation
            }

            camera.dumpstats()
        })

        active = true
    }
}
