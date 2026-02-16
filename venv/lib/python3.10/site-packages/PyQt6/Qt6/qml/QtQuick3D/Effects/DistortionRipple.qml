// Copyright (C) 2020 The Qt Company Ltd.
// SPDX-License-Identifier: LicenseRef-Qt-Commercial OR GPL-3.0-only

import QtQuick
import QtQuick3D

Effect {
    property real radius: 100.0             // 0 - 100
    property real distortionWidth: 10.0     // 2 - 100
    property real distortionHeight: 10.0    // 0 - 100
    property real distortionPhase: 0.0      // 0 - 360
    property vector2d center: Qt.vector2d(0.5, 0.5)

    Shader {
        id: distortionVert
        stage: Shader.Vertex
        shader: "qrc:/qtquick3deffects/shaders/distortion.vert"
    }

    Shader {
        id: distortionFrag
        stage: Shader.Fragment
        shader: "qrc:/qtquick3deffects/shaders/distortionripple.frag"
    }

    passes: [
        Pass {
            shaders: [ distortionVert, distortionFrag ]
        }
    ]
}
