// Copyright (C) 2020 The Qt Company Ltd.
// SPDX-License-Identifier: LicenseRef-Qt-Commercial OR GPL-3.0-only

import QtQuick
import QtQuick3D

Effect {
    property vector3d bottomColor: Qt.vector3d(0.0, 0.0, 0.0)
    property vector3d topColor: Qt.vector3d(1.0, 1.0, 1.0)

    Shader {
        id: additivecolorgradient
        stage: Shader.Fragment
        shader: "qrc:/qtquick3deffects/shaders/additivecolorgradient.frag"
    }

    passes: [
        Pass {
            shaders: [ additivecolorgradient ]
        }
    ]
}
