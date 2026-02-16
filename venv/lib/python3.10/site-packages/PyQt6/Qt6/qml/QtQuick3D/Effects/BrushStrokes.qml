// Copyright (C) 2020 The Qt Company Ltd.
// SPDX-License-Identifier: LicenseRef-Qt-Commercial OR GPL-3.0-only

import QtQuick
import QtQuick3D

Effect {
    property TextureInput noiseSample: TextureInput {
        texture: Texture {
            tilingModeHorizontal: Texture.Repeat
            tilingModeVertical: Texture.Repeat
            source: "qrc:/qtquick3deffects/maps/brushnoise.png"
        }
    }
    property real brushLength: 1.0  // 0 - 3
    property real brushSize: 100.0  // 10 - 200
    property real brushAngle: 45.0
    readonly property real sinAlpha: Math.sin(degrees_to_radians(brushAngle))
    readonly property real cosAlpha: Math.cos(degrees_to_radians(brushAngle))

    function degrees_to_radians(degrees) {
        var pi = Math.PI;
        return degrees * (pi/180);
    }

    Shader {
        id: brushstrokes
        stage: Shader.Fragment
        shader: "qrc:/qtquick3deffects/shaders/brushstrokes.frag"
    }

    passes: [
        Pass {
            shaders: [ brushstrokes ]
        }
    ]
}
