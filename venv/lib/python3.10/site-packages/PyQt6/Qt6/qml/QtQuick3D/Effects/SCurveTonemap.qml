// Copyright (C) 2020 The Qt Company Ltd.
// SPDX-License-Identifier: LicenseRef-Qt-Commercial OR GPL-3.0-only

import QtQuick
import QtQuick3D

Effect {
    property real shoulderSlope: 1.0   // 0.0 - 3.0
    property real shoulderEmphasis: 0  // -1.0 - 1.0
    property real toeSlope: 1.0        // 0.0 - 3.0
    property real toeEmphasis: 0       // -1.0 - 1.0
    property real contrastBoost: 0     // -1.0 - 2.0
    property real saturationLevel: 1   // 0.0 - 2.0
    property real gammaValue: 2.2      // 0.1 - 8.0
    property bool useExposure: false
    property real whitePoint: 1.0      // 0.01 - 128.0
    property real exposureValue: 1.0   // 0.01 - 16.0

    Shader {
        id: tonemapShader
        stage: Shader.Fragment
        shader: "qrc:/qtquick3deffects/shaders/scurvetonemap.frag"
    }

    Buffer {
        // LDR output
        id: defaultOutput
        format: Buffer.RGBA8
    }

    passes: [
        Pass {
            shaders: [ tonemapShader ]
            output: defaultOutput
        }
    ]
}
