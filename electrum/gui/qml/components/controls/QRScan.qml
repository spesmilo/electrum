import QtQuick
import QtQuick.Controls
import QtMultimedia
import QtQml

import org.electrum 1.0

Item {
    id: scanner

    property bool active: false
    property string url
    property string scanData
    property string hint

    signal found

    function restart() {
        console.log('qrscan.restart')
        scanData = ''
        qr.reset()
        start()
    }

    function start() {
        console.log('qrscan.start')
        loader.item.startTimer.start()
    }

    function stop() {
        console.log('qrscan.stop')
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

                Component.onCompleted: {
                    startTimer.start()
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
                cameraDevice: mediaDevices.defaultVideoInput
                active: scanner.active
                focusMode: Camera.FocusModeAutoNear
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
            console.log('QR DATA: ' + qr.data)
            scanner.active = false
            scanner.scanData = qr.data
            scanner.found()
        }
    }

    QRParser {
        id: qr
        videoSink: loader.item.vo.videoSink
    }

}
