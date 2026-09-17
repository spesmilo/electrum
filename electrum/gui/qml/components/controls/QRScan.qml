import QtQuick
import QtQuick.Controls
import QtMultimedia
import QtQml

import org.electrum 1.0

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
        loader.item.startTimer.start()
    }

    function stop() {
        console.log('qrscan.stop')
        loader.item.startTimer.stop()
        scanner.active = false
    }

    Item {
        id: points
        z: 100
        anchors.fill: parent
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
            property alias startTimer: _startTimer

            VideoOutput {
                id: _vo
                anchors.fill: parent

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
                InfoTextArea {
                    visible: scanner.hint
                    background.opacity: 0.5
                    iconStyle: InfoTextArea.IconStyle.None
                    horizontalAlignment: Text.AlignHCenter
                    anchors {
                        top: parent.top
                        topMargin: constants.paddingXLarge
                        left: parent.left
                        leftMargin: constants.paddingXXLarge
                        right: parent.right
                        rightMargin: constants.paddingXXLarge
                    }
                    text: scanner.hint
                }
            }

            ImageCapture {
                id: _ic

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

            Timer {
                id: _startTimer
                interval: 500
                repeat: false
                onTriggered: scanner.active = true
            }

        }
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
