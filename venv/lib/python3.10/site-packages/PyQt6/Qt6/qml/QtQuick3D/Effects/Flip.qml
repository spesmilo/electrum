// Copyright (C) 2020 The Qt Company Ltd.
// SPDX-License-Identifier: LicenseRef-Qt-Commercial OR GPL-3.0-only

import QtQuick
import QtQuick3D

Effect {
    property bool flipHorizontally: true
    property bool flipVertically: true

    Shader {
        id: flip
        stage: Shader.Fragment
        shader: "qrc:/qtquick3deffects/shaders/flip.frag"
    }

    passes: [
        Pass {
            shaders: [ flip ]
        }
    ]
}
