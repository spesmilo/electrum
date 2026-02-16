// Copyright (C) 2019 The Qt Company Ltd.
// SPDX-License-Identifier: LicenseRef-Qt-Commercial OR GPL-3.0-only

import QtQuick
import QtQuick3D

View3D {
    width: 400
    height: 400
    environment: sceneEnvironment

    SceneEnvironment {
        id: sceneEnvironment
        antialiasingMode: SceneEnvironment.MSAA
        antialiasingQuality: SceneEnvironment.High
    }

    Node {
        id: scene

        DirectionalLight {
            id: directionalLight
        }

        PerspectiveCamera {
            id: sceneCamera
            z: 350
        }

        Model {
            id: cubeModel
            eulerRotation.x: 30
            eulerRotation.y: 45

            source: "#Cube"
        }
    }
}
