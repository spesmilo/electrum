// Copyright (C) 2020 The Qt Company Ltd.
// SPDX-License-Identifier: LicenseRef-Qt-Commercial OR GPL-3.0-only

import QtQuick
import QtQuick3D

Effect {
    readonly property TextureInput downsample2: TextureInput {
        texture: Texture {}
    }
    readonly property TextureInput downsample4: TextureInput {
        texture: Texture {}
    }
    property real gamma: 1              // 0.1 - 4
    property real exposure: 0           // -9 - 9
    readonly property real exposureExp2: Math.pow(2, exposure)
    property real bloomThreshold: 1
    property real blurFalloff: 0        // 0 - 10
    readonly property real negativeBlurFalloffExp2: Math.pow(2, -blurFalloff)
    property real tonemappingLerp: 1    // 0 - 1
    property real channelThreshold: 1
    readonly property real poissonRotation: 0
    readonly property real poissonDistance: 4

    Shader {
        id: luminosityVert
        stage: Shader.Vertex
        shader: "qrc:/qtquick3deffects/shaders/luminosity.vert"
    }
    Shader {
        id: luminosityFrag
        stage: Shader.Fragment
        shader: "qrc:/qtquick3deffects/shaders/luminosity.frag"
    }

    Shader {
        id: blurVert
        stage: Shader.Vertex
        shader: "qrc:/qtquick3deffects/shaders/poissonblur.vert"
    }
    Shader {
        id: blurFrag
        stage: Shader.Fragment
        shader: "qrc:/qtquick3deffects/shaders/poissonblur.frag"
    }

    Shader {
        id: combiner
        stage: Shader.Fragment
        shader: "qrc:/qtquick3deffects/shaders/combiner.frag"
    }

    Buffer {
        id: luminosity_buffer2
        name: "luminosity_buffer2"
        format: Buffer.RGBA8
        textureFilterOperation: Buffer.Linear
        textureCoordOperation: Buffer.ClampToEdge
        bufferFlags: Buffer.None
        sizeMultiplier: 0.5
    }
    Buffer {
        id: downsample_buffer2
        name: "downsample_buffer2"
        format: Buffer.RGBA8
        textureFilterOperation: Buffer.Linear
        textureCoordOperation: Buffer.ClampToEdge
        bufferFlags: Buffer.None
        sizeMultiplier: 0.5
    }
    Buffer {
        id: downsample_buffer4
        name: "downsample_buffer4"
        format: Buffer.RGBA8
        textureFilterOperation: Buffer.Linear
        textureCoordOperation: Buffer.ClampToEdge
        bufferFlags: Buffer.None
        sizeMultiplier: 0.25
    }

    passes: [
        Pass {
            shaders: [ luminosityVert, luminosityFrag ]
            output: downsample_buffer2
        },
        Pass {
            shaders: [ luminosityVert, luminosityFrag ]
            commands: BufferInput {
                buffer: downsample_buffer2
            }
            output: luminosity_buffer2
        },
        Pass {
            shaders: [ blurVert, blurFrag ]
            commands: BufferInput {
                buffer: luminosity_buffer2
            }
            output: downsample_buffer2
        },
        Pass {
            shaders: [ blurVert, blurFrag ]
            commands: [
                SetUniformValue {
                    target: "poissonRotation"
                    value: 0.62831
                },
                BufferInput {
                    buffer: luminosity_buffer2
                }
            ]
            output: downsample_buffer4
        },
        Pass {
            shaders: [ combiner ]
            commands: [
                BufferInput {
                    sampler: "downsample2"
                    buffer: downsample_buffer2
                },
                BufferInput {
                    sampler: "downsample4"
                    buffer: downsample_buffer4
                }
            ]
        }
    ]
}
