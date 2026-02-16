// Copyright (C) 2020 The Qt Company Ltd.
// SPDX-License-Identifier: LicenseRef-Qt-Commercial OR GPL-3.0-only

import QtQuick
import QtQuick3D

Effect {
    property real redStrength: 1.0      // 0 - 2
    property real greenStrength: 1.5    // 0 - 2
    property real blueStrength: 1.0     // 0 - 2
    property real saturation: 0.0       // -1 - 1

    Shader {
        id: colormaster
        stage: Shader.Fragment
        shader: "qrc:/qtquick3deffects/shaders/colormaster.frag"
    }

    passes: [
        Pass {
            shaders: [ colormaster ]
        }
    ]
}
