// Copyright (C) 2022 The Qt Company Ltd.
// SPDX-License-Identifier: LicenseRef-Qt-Commercial OR GPL-3.0-only

import QtQuick
import QtQuick3D

Item {
    id: root
    required property Node origin
    required property Camera camera

    property real xSpeed: 0.1
    property real ySpeed: 0.1

    property bool xInvert: false
    property bool yInvert: true

    property bool mouseEnabled: true
    property bool panEnabled: true
    property bool automaticClipping: true

    property alias acceptedButtons: dragHandler.acceptedButtons

    readonly property bool inputsNeedProcessing: status.useMouse || status.isPanning

    implicitWidth: parent.width
    implicitHeight: parent.height

    Connections {
        enabled: root.automaticClipping
        target: root.camera
        function onZChanged() {
            // Adjust near/far values based on distance
            let distance = root.camera.z
            if (distance < 1) {
                root.camera.clipNear = 0.01
                root.camera.clipFar = 100
                if (root.camera.z === 0) {
                    console.warn("camera z set to 0, setting it to near clip")
                    root.camera.z = root.camera.clipNear
                }
            } else if (distance < 100) {
                root.camera.clipNear = 0.1
                root.camera.clipFar = 1000
            } else {
                root.camera.clipNear = 1
                root.camera.clipFar = 10000
            }
        }
    }

    DragHandler {
        id: dragHandler
        target: null
        enabled: root.mouseEnabled
        acceptedModifiers: Qt.NoModifier
        onCentroidChanged: {
            root.mouseMoved(Qt.vector2d(centroid.position.x, centroid.position.y), false);
        }

        onActiveChanged: {
            if (active)
                root.mousePressed(Qt.vector2d(centroid.position.x, centroid.position.y));
            else
                root.mouseReleased(Qt.vector2d(centroid.position.x, centroid.position.y));
        }
    }

    DragHandler {
        id: ctrlDragHandler
        target: null
        enabled: root.mouseEnabled && root.panEnabled
        acceptedButtons: root.acceptedButtons
        acceptedModifiers: Qt.ControlModifier
        onCentroidChanged: {
            root.panEvent(Qt.vector2d(centroid.position.x, centroid.position.y));
        }

        onActiveChanged: {
            if (active)
                root.startPan(Qt.vector2d(centroid.position.x, centroid.position.y));
            else
                root.endPan();
        }
    }

    PinchHandler {
        id: pinchHandler
        target: null
        enabled: root.mouseEnabled

        onTranslationChanged: (delta) => {
            if (!root.panEnabled)
                return;
            delta.x = -(delta.x / root.width) * root.camera.z;
            delta.y = (delta.y / root.height) * root.camera.z;

            let movement = Qt.vector3d(0, 0, 0)
            // X Movement
            let xDirection = root.origin.right
            movement = movement.plus(Qt.vector3d(xDirection.x * delta.x,
                                                 xDirection.y * delta.x,
                                                 xDirection.z * delta.x));
            // Y Movement
            let yDirection = root.origin.up
            movement = movement.plus(Qt.vector3d(yDirection.x * delta.y,
                                                 yDirection.y * delta.y,
                                                 yDirection.z * delta.y));

            root.origin.position = root.origin.position.plus(movement)
        }

        onScaleChanged: (delta) => {
            root.camera.z = root.camera.z * (1 / delta)
        }
    }

    TapHandler {
        acceptedButtons: root.acceptedButtons
        onTapped: root.forceActiveFocus() // qmllint disable signal-handler-parameters
    }

    WheelHandler {
        id: wheelHandler
        orientation: Qt.Vertical
        target: null
        enabled: root.mouseEnabled
        acceptedDevices: PointerDevice.Mouse | PointerDevice.TouchPad
        onWheel: event => {
            let delta = -event.angleDelta.y * 0.01;
            root.camera.z += root.camera.z * 0.1 * delta
        }
    }

    function mousePressed(newPos) {
        root.forceActiveFocus()
        status.currentPos = newPos
        status.lastPos = newPos
        status.useMouse = true;
    }

    function mouseReleased(newPos) {
        status.useMouse = false;
    }

    function mouseMoved(newPos: vector2d) {
        status.currentPos = newPos;
    }

    function startPan(pos: vector2d) {
        status.isPanning = true;
        status.currentPanPos = pos;
        status.lastPanPos = pos;
    }

    function endPan() {
        status.isPanning = false;
    }

    function panEvent(newPos: vector2d) {
        status.currentPanPos = newPos;
    }

    FrameAnimation {
        id: updateTimer
        running: root.inputsNeedProcessing
        onTriggered: status.processInput(frameTime * 100)
    }

    QtObject {
        id: status

        property bool useMouse: false
        property bool isPanning: false

        property vector2d lastPos: Qt.vector2d(0, 0)
        property vector2d lastPanPos: Qt.vector2d(0, 0)
        property vector2d currentPos: Qt.vector2d(0, 0)
        property vector2d currentPanPos: Qt.vector2d(0, 0)

        function negate(vector) {
            return Qt.vector3d(-vector.x, -vector.y, -vector.z)
        }

        function processInput(frameDelta) {
            if (useMouse) {
                // Get the delta
                var rotationVector = root.origin.eulerRotation;
                var delta = Qt.vector2d(lastPos.x - currentPos.x,
                                        lastPos.y - currentPos.y);
                // rotate x
                var rotateX = delta.x * root.xSpeed * frameDelta
                if (root.xInvert)
                    rotateX = -rotateX;
                rotationVector.y += rotateX;

                // rotate y
                var rotateY = delta.y * -root.ySpeed * frameDelta
                if (root.yInvert)
                    rotateY = -rotateY;
                rotationVector.x += rotateY;
                root.origin.setEulerRotation(rotationVector);
                lastPos = currentPos;
            }
            if (isPanning) {
                let delta = currentPanPos.minus(lastPanPos);
                delta.x = -delta.x

                delta.x = (delta.x / root.width) * root.camera.z * frameDelta
                delta.y = (delta.y / root.height) * root.camera.z * frameDelta

                let velocity = Qt.vector3d(0, 0, 0)
                // X Movement
                let xDirection = root.origin.right
                velocity = velocity.plus(Qt.vector3d(xDirection.x * delta.x,
                                                     xDirection.y * delta.x,
                                                     xDirection.z * delta.x));
                // Y Movement
                let yDirection = root.origin.up
                velocity = velocity.plus(Qt.vector3d(yDirection.x * delta.y,
                                                     yDirection.y * delta.y,
                                                     yDirection.z * delta.y));

                root.origin.position = root.origin.position.plus(velocity)

                lastPanPos = currentPanPos
            }
        }
    }

}
