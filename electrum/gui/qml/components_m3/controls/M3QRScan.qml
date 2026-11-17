import QtQuick
import QtQuick.Controls
import QtMultimedia
import QtQml

import org.electrum 1.0

// QR code scanner (camera viewfinder) of the Material 3 GUI, used by the Material 3 ScanDialog.
// repeats: components/controls/QRScan.qml:8-171 @ e6df7e1c8 (the API: active, url, hint, foundText(data),
// restart(), start(), stop(); start() asks for the camera permission (AppController.requestPermission) and
// activates; the camera is loaded by a Loader and started once loaded; the back camera is preferred (the Android
// FFmpeg backend marks no default); the camera is active only while `active`, the application is active and the
// permission is granted (AppController.hasPermission), so it starts after the permission prompt; tap to focus
// captures one frame for QRParser.decodeFrameOneShot; QRParser reads the video sink, the first data found
// deactivates the scanner and is emitted by foundText).
// Differences: the hint is a Material 3 chip (inverse surface) instead of the InfoTextArea, and the square in the
// middle has a rounded frame; the unused `points` item and the marker component `r` of the classic file (it
// refers to a `_pointsVisible` that does not exist) are left out.
Item {
    id: scanner

    property bool active: false
    property string url
    property string hint

    readonly property string cameraPermission: 'android.permission.CAMERA'

    signal foundText(data: string)

    function restart() {
        console.log('qrscan.restart')
        qr.reset()
        start()
    }

    function start() {
        console.log('qrscan.start')
        AppController.requestPermission(scanner.cameraPermission)
        scanner.active = true
    }

    function stop() {
        console.log('qrscan.stop')
        scanner.active = false
    }

    Rectangle {
        // the camera image is dark; until it shows, the viewfinder is black (as the classic VideoOutput)
        anchors.fill: parent
        color: 'black'
    }

    Loader {
        id: loader
        anchors.fill: parent
        sourceComponent: scancomp
        onLoaded: scanner.start()
        onStatusChanged: {
            if (loader.status == Loader.Ready) {
                console.log('camera loaded')
            } else if (loader.status == Loader.Error) {
                console.log('camera load error')
            }
        }
    }

    Component {
        id: scancomp

        Item {
            property alias vo: _vo
            property alias ic: _ic

            VideoOutput {
                id: _vo
                anchors.fill: parent

                fillMode: VideoOutput.PreserveAspectCrop

                // the scan square: the full width (or height, in landscape) in the middle, the rest dimmed
                readonly property real _side: Math.min(width, height)

                Rectangle {
                    width: parent.width
                    height: (parent.height - parent._side) / 2
                    anchors.top: parent.top
                    color: Qt.rgba(0, 0, 0, 0.5)
                }
                Rectangle {
                    width: parent.width
                    height: (parent.height - parent._side) / 2
                    anchors.bottom: parent.bottom
                    color: Qt.rgba(0, 0, 0, 0.5)
                }
                Rectangle {
                    width: (parent.width - parent._side) / 2
                    height: parent._side
                    anchors.left: parent.left
                    anchors.verticalCenter: parent.verticalCenter
                    color: Qt.rgba(0, 0, 0, 0.5)
                }
                Rectangle {
                    width: (parent.width - parent._side) / 2
                    height: parent._side
                    anchors.right: parent.right
                    anchors.verticalCenter: parent.verticalCenter
                    color: Qt.rgba(0, 0, 0, 0.5)
                }
                // the frame of the scan square
                Rectangle {
                    anchors.centerIn: parent
                    width: parent._side - 2 * m3.space32
                    height: width
                    radius: m3.radiusL
                    color: 'transparent'
                    border.width: 2
                    border.color: 'white'
                    opacity: 0.8
                }

                Rectangle {
                    visible: scanner.hint
                    anchors {
                        top: parent.top
                        topMargin: m3.space24
                        horizontalCenter: parent.horizontalCenter
                    }
                    width: Math.min(hintText.implicitWidth, parent.width - 2 * m3.space24)
                    height: hintText.implicitHeight
                    radius: m3.radiusS
                    color: m3.inverseSurface
                    opacity: 0.9

                    M3Text {
                        id: hintText
                        width: parent.width
                        leftPadding: m3.space16
                        rightPadding: m3.space16
                        topPadding: m3.space12
                        bottomPadding: m3.space12
                        role: 'bodyMedium'
                        color: m3.inverseSurfaceOn
                        wrapMode: Text.Wrap
                        lineHeightMode: Text.ProportionalHeight
                        lineHeight: 1.0
                        horizontalAlignment: Text.AlignHCenter
                        text: scanner.hint
                    }
                }

                TapHandler {
                    // "tap-to-focus", trigger an image capture which forces an autofocus
                    onTapped: if (_ic.readyForCapture) _ic.capture()
                }
            }

            ImageCapture {
                id: _ic
                onImageAvailable: (requestId, frame) => qr.decodeFrameOneShot(frame)
            }

            MediaDevices {
                id: mediaDevices
            }

            Camera {
                id: camera
                cameraDevice: {
                    // The Android FFmpeg backend does not mark a default camera.
                    for (var device of mediaDevices.videoInputs) {
                        if (device.position === CameraDevice.BackFace)
                            return device
                    }
                    return mediaDevices.defaultVideoInput
                }
                // The permission prompt pauses the activity, so the application
                // state change re-evaluates this binding after the user answers.
                active: scanner.active
                    && Qt.application.state === Qt.ApplicationActive
                    && AppController.hasPermission(scanner.cameraPermission)
                customFocusPoint: Qt.point(0.5, 0.5)

                onErrorOccurred: {
                    console.log('camera error: ' + errorString)
                }
            }

            CaptureSession {
                videoOutput: _vo
                imageCapture: _ic
                camera: camera
            }
        }
    }

    Connections {
        target: qr
        function onDataChanged() {
            if (!qr.data)
                return
            scanner.active = false
            scanner.foundText(qr.data)
        }
    }

    QRParser {
        id: qr
        videoSink: loader.item.vo.videoSink
    }

}
