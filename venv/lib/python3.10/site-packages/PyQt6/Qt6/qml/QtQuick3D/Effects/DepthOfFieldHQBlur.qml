// Copyright (C) 2020 The Qt Company Ltd.
// SPDX-License-Identifier: LicenseRef-Qt-Commercial OR GPL-3.0-only

import QtQuick
import QtQuick3D

Effect {
    readonly property TextureInput sourceSampler: TextureInput {
        texture: Texture {}
    }
    property real focusDistance: 600
    property real focusRange: 100
    property real blurAmount: 4

    Shader {
        id: downsampleVert
        stage: Shader.Vertex
        shader: "qrc:/qtquick3deffects/shaders/downsample.vert"
    }
    Shader {
        id: downsampleFrag
        stage: Shader.Fragment
        shader: "qrc:/qtquick3deffects/shaders/downsample.frag"
    }

    Shader {
        id: blurVert
        stage: Shader.Vertex
        shader: "qrc:/qtquick3deffects/shaders/depthoffieldblur.vert"
    }
    Shader {
        id: blurFrag
        stage: Shader.Fragment
        shader: "qrc:/qtquick3deffects/shaders/depthoffieldblur.frag"
    }

    Buffer {
        id: downsampleBuffer
        name: "downsampleBuffer"
        format: Buffer.RGBA8
        textureFilterOperation: Buffer.Linear
        textureCoordOperation: Buffer.ClampToEdge
        sizeMultiplier: 0.5
    }

    passes: [
        Pass {
            shaders: [ downsampleVert, downsampleFrag ]
            output: downsampleBuffer
        },
        Pass {
            shaders: [ blurVert, blurFrag ]
            commands: [
                // INPUT is the texture for downsampleBuffer
                BufferInput {
                    buffer: downsampleBuffer
                },
                // the actual input texture is exposed as sourceSampler
                BufferInput {
                    sampler: "sourceSampler"
                }
            ]
        }
    ]
}
