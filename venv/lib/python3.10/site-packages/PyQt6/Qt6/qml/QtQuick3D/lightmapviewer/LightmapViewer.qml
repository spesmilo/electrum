// Copyright (C) 2025 The Qt Company Ltd.
// SPDX-License-Identifier: LicenseRef-Qt-Commercial OR GPL-3.0-only WITH Qt-GPL-exception-1.0
import QtQuick
import QtQuick.Controls
import QtQuick.Layouts
import QtQuick.Window
import QtQuick.Dialogs

import LightmapFile 1.0

ApplicationWindow {
    width: 640
    height: 480
    visible: true
    title: qsTr("Lightmap Viewer")

    id: window

    property string selectedKey: listView.model[0]
    property real imageZoom: 1
    property real imageCenterX: 0
    property real imageCenterY: 0

    function clampImagePosition() {
        // If the image is smaller than the scroll view, center it
        if (image.width <= scrollView.width) {
            imageCenterX = 0
        } else {
            const maxOffsetX = (image.width - scrollView.width) / 2
            imageCenterX = Math.max(-maxOffsetX, Math.min(imageCenterX,
                                                          maxOffsetX))
        }

        if (image.height <= scrollView.height) {
            imageCenterY = 0
        } else {
            const maxOffsetY = (image.height - scrollView.height) / 2
            imageCenterY = Math.max(-maxOffsetY, Math.min(imageCenterY,
                                                          maxOffsetY))
        }
    }

    header: ToolBar {
        RowLayout {
            Button {
                text: qsTr("Open Lightmap")
                onClicked: fileDialog.open()
            }

            Rectangle {
                width: 1
                color: "darkgray"
                Layout.fillHeight: true
                Layout.alignment: Qt.AlignVCenter
            }

            Label {
                text: "Zoom: " + window.imageZoom.toFixed(1)
            }

            Rectangle {
                width: 1
                color: "darkgray"
                Layout.fillHeight: true
                Layout.alignment: Qt.AlignVCenter
            }

            Switch {
                id: alphaSwitch
                padding: 0
                checked: true
                text: "Alpha"
            }

            Rectangle {
                width: 1
                color: "darkgray"
                Layout.fillHeight: true
                Layout.alignment: Qt.AlignVCenter
            }

            Text {
                text: "Path: " + LightmapFile.source
            }
        }
    }

    FileDialog {
        id: fileDialog
        onAccepted: {
            LightmapFile.source = selectedFile
            LightmapFile.loadData()
        }
    }

    Shortcut {
        sequences: [StandardKey.Open]
        onActivated: {
            fileDialog.open()
        }
    }

    SplitView {
        anchors.fill: parent
        orientation: Qt.Horizontal

        focus: true
        Keys.onPressed: event => {
                            if (event.key === Qt.Key_Up) {
                                listView.currentIndex = Math.max(
                                    0, listView.currentIndex - 1)
                                selectedKey = listView.model[listView.currentIndex]
                            } else if (event.key === Qt.Key_Down) {
                                listView.currentIndex = Math.min(
                                    listView.model.length - 1,
                                    listView.currentIndex + 1)
                                selectedKey = listView.model[listView.currentIndex]
                            }
                            clampImagePosition()
                        }
        ListView {
            id: listView
            SplitView.preferredWidth: 100
            SplitView.minimumWidth: 50
            model: LightmapFile.dataList
            delegate: Text {
                text: modelData
                MouseArea {
                    anchors.fill: parent
                    onClicked: {
                        listView.currentIndex = index
                        selectedKey = modelData // Select this item
                    }
                }
            }
            highlight: Rectangle {
                color: "lightsteelblue"
                radius: 1
            }
        }

        Rectangle {
            id: scrollView
            clip: true
            color: "black"

            property real lastMouseX: 0
            property real lastMouseY: 0

            onWidthChanged: {
                clampImagePosition()
            }
            onHeightChanged: {
                clampImagePosition()
            }

            MouseArea {
                id: mouseArea
                property bool dragging: false
                anchors.fill: parent
                onPressed: mouse => {
                               scrollView.lastMouseX = mouse.x
                               scrollView.lastMouseY = mouse.y
                               dragging = true
                           }
                onReleased: mouse => {
                                dragging = false
                            }

                onPositionChanged: mouse => {
                                       var dx = mouse.x - scrollView.lastMouseX
                                       var dy = mouse.y - scrollView.lastMouseY

                                       scrollView.lastMouseX = mouse.x
                                       scrollView.lastMouseY = mouse.y

                                       imageCenterX += dx
                                       imageCenterY += dy

                                       clampImagePosition()
                                   }
                cursorShape: mouseArea.dragging ? Qt.ClosedHandCursor : Qt.ArrowCursor

                onWheel: event => {
                             const oldZoom = imageZoom
                             const zoomDelta = event.angleDelta.y / 256
                             const newZoom = Math.max(
                                 1, Math.min(32, oldZoom + zoomDelta))

                             if (newZoom === oldZoom)
                             return

                             // Adjust center offset so the same point remains at the center
                             const scaleFactor = newZoom / oldZoom
                             imageCenterX *= scaleFactor
                             imageCenterY *= scaleFactor

                             imageZoom = newZoom
                             clampImagePosition()

                             event.accepted = true
                         }
            }

            Image {
                id: baseGrid
                anchors.fill: scrollView
                source: "grid.png"
                fillMode: Image.Tile
                opacity: 0.75
            }

            Rectangle {
                width: image.width + (border.width * 2)
                height: image.height + (border.width * 2)
                x: image.x - border.width
                y: image.y - border.width
                color: "white" // This is the border color

                border.width: 0
                border.color: "white"
                opacity: 0.25
            }

            Image {
                id: image
                x: Math.round(parent.width / 2 - width / 2) + imageCenterX
                y: Math.round(parent.height / 2 - height / 2) + imageCenterY
                source: `image://lightmaps/key=${selectedKey}&file=${LightmapFile.source}&alpha=${alphaSwitch.checked}`
                onWidthChanged: clampImagePosition()
                onHeightChanged: clampImagePosition()
                fillMode: Image.PreserveAspectFit
                smooth: false
                antialiasing: false

                // Let the image scale visibly
                width: sourceSize.width * imageZoom
                height: sourceSize.height * imageZoom
            }
        }
    }

    DropArea {
        id: dropArea
        anchors.fill: parent
        onEntered: (drag) => {
            drag.accept(Qt.LinkAction)
        }
            // Just take first url if several
        onDropped: (drop) => {
            if (drop.hasUrls) {
                LightmapFile.source = drop.urls[0]
                LightmapFile.loadData()
            }
        }
    }
}
