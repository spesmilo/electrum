// Copyright (C) 2019 The Qt Company Ltd.
// SPDX-License-Identifier: LicenseRef-Qt-Commercial OR GPL-3.0-only

import QtQuick
import QtQuick3D

Item {
    id: root
    property Node controlledObject: undefined

    property real speed: 1
    property real shiftSpeed: 3

    property real forwardSpeed: 5
    property real backSpeed: 5
    property real rightSpeed: 5
    property real leftSpeed: 5
    property real upSpeed: 5
    property real downSpeed: 5
    property real xSpeed: 0.1
    property real ySpeed: 0.1

    property bool xInvert: false
    property bool yInvert: true

    property bool mouseEnabled: true
    property bool keysEnabled: true

    readonly property bool inputsNeedProcessing: status.moveForward | status.moveBack
                                                 | status.moveLeft | status.moveRight
                                                 | status.moveUp | status.moveDown
                                                 | status.useMouse

    property alias acceptedButtons: dragHandler.acceptedButtons



    implicitWidth: parent.width
    implicitHeight: parent.height
    focus: keysEnabled

    DragHandler {
        id: dragHandler
        target: null
        enabled: root.mouseEnabled
        onCentroidChanged: {
            root.mouseMoved(Qt.vector2d(centroid.position.x, centroid.position.y));
        }

        onActiveChanged: {
            if (active)
                root.mousePressed(Qt.vector2d(centroid.position.x, centroid.position.y));
            else
                root.mouseReleased(Qt.vector2d(centroid.position.x, centroid.position.y));
        }
    }

    TapHandler {
        acceptedButtons: dragHandler.acceptedButtons
        onTapped: root.forceActiveFocus() // qmllint disable signal-handler-parameters
    }

    Keys.onPressed: (event)=> { if (keysEnabled && !event.isAutoRepeat) handleKeyPress(event) }
    Keys.onReleased: (event)=> { if (keysEnabled && !event.isAutoRepeat) handleKeyRelease(event) }

    function mousePressed(newPos) {
        root.forceActiveFocus()
        status.currentPos = newPos
        status.lastPos = newPos
        status.useMouse = true;
    }

    function mouseReleased(newPos) {
        status.useMouse = false;
    }

    function mouseMoved(newPos) {
        status.currentPos = newPos;
    }

    function forwardPressed() {
        status.moveForward = true
        status.moveBack = false
    }

    function forwardReleased() {
        status.moveForward = false
    }

    function backPressed() {
        status.moveBack = true
        status.moveForward = false
    }

    function backReleased() {
        status.moveBack = false
    }

    function rightPressed() {
        status.moveRight = true
        status.moveLeft = false
    }

    function rightReleased() {
        status.moveRight = false
    }

    function leftPressed() {
        status.moveLeft = true
        status.moveRight = false
    }

    function leftReleased() {
        status.moveLeft = false
    }

    function upPressed() {
        status.moveUp = true
        status.moveDown = false
    }

    function upReleased() {
        status.moveUp = false
    }

    function downPressed() {
        status.moveDown = true
        status.moveUp = false
    }

    function downReleased() {
        status.moveDown = false
    }

    function shiftPressed() {
        status.shiftDown = true
    }

    function shiftReleased() {
        status.shiftDown = false
    }

    function handleKeyPress(event)
    {
        switch (event.key) {
        case Qt.Key_W:
        case Qt.Key_Up:
            forwardPressed();
            break;
        case Qt.Key_S:
        case Qt.Key_Down:
            backPressed();
            break;
        case Qt.Key_A:
        case Qt.Key_Left:
            leftPressed();
            break;
        case Qt.Key_D:
        case Qt.Key_Right:
            rightPressed();
            break;
        case Qt.Key_R:
        case Qt.Key_PageUp:
            upPressed();
            break;
        case Qt.Key_F:
        case Qt.Key_PageDown:
            downPressed();
            break;
        case Qt.Key_Shift:
            shiftPressed();
            break;
        }
    }

    function handleKeyRelease(event)
    {
        switch (event.key) {
        case Qt.Key_W:
        case Qt.Key_Up:
            forwardReleased();
            break;
        case Qt.Key_S:
        case Qt.Key_Down:
            backReleased();
            break;
        case Qt.Key_A:
        case Qt.Key_Left:
            leftReleased();
            break;
        case Qt.Key_D:
        case Qt.Key_Right:
            rightReleased();
            break;
        case Qt.Key_R:
        case Qt.Key_PageUp:
            upReleased();
            break;
        case Qt.Key_F:
        case Qt.Key_PageDown:
            downReleased();
            break;
        case Qt.Key_Shift:
            shiftReleased();
            break;
        }
    }

    FrameAnimation {
        id: updateTimer
        running: root.inputsNeedProcessing
        onTriggered: status.processInput(frameTime * 100)
    }

    QtObject {
        id: status

        property bool moveForward: false
        property bool moveBack: false
        property bool moveLeft: false
        property bool moveRight: false
        property bool moveUp: false
        property bool moveDown: false
        property bool shiftDown: false
        property bool useMouse: false

        property vector2d lastPos: Qt.vector2d(0, 0)
        property vector2d currentPos: Qt.vector2d(0, 0)

        function updatePosition(vector, speed, position)
        {
            if (shiftDown)
                speed *= root.shiftSpeed;
            else
                speed *= root.speed

            var direction = vector;
            var velocity = Qt.vector3d(direction.x * speed,
                                       direction.y * speed,
                                       direction.z * speed);
            controlledObject.position = Qt.vector3d(position.x + velocity.x,
                                                    position.y + velocity.y,
                                                    position.z + velocity.z);
        }

        function negate(vector) {
            return Qt.vector3d(-vector.x, -vector.y, -vector.z)
        }

        function processInput(frameDelta) {
            if (root.controlledObject == undefined)
                return;

            if (moveForward)
                updatePosition(root.controlledObject.forward, root.forwardSpeed * frameDelta, root.controlledObject.position);
            else if (moveBack)
                updatePosition(negate(root.controlledObject.forward), root.backSpeed * frameDelta, root.controlledObject.position);

            if (moveRight)
                updatePosition(root.controlledObject.right, root.rightSpeed * frameDelta, root.controlledObject.position);
            else if (moveLeft)
                updatePosition(negate(root.controlledObject.right), root.leftSpeed * frameDelta, root.controlledObject.position);

            if (moveDown)
                updatePosition(negate(root.controlledObject.up), root.downSpeed * frameDelta, root.controlledObject.position);
            else if (moveUp)
                updatePosition(root.controlledObject.up, root.upSpeed * frameDelta, root.controlledObject.position);

            if (useMouse) {
                // Get the delta
                var rotationVector = root.controlledObject.eulerRotation;
                var delta = Qt.vector2d(lastPos.x - currentPos.x,
                                        lastPos.y - currentPos.y);
                // rotate x
                var rotateX = delta.x * xSpeed * frameDelta
                if (xInvert)
                    rotateX = -rotateX;
                rotationVector.y += rotateX;

                // rotate y
                var rotateY = delta.y * -ySpeed * frameDelta
                if (yInvert)
                    rotateY = -rotateY;
                rotationVector.x += rotateY;
                controlledObject.setEulerRotation(rotationVector);
                lastPos = currentPos;
            }
        }
    }
}
