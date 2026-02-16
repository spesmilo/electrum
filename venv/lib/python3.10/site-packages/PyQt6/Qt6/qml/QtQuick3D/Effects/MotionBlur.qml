// Copyright (C) 2020 The Qt Company Ltd.
// SPDX-License-Identifier: LicenseRef-Qt-Commercial OR GPL-3.0-only

import QtQuick
import QtQuick3D

Effect {
    id: effectRoot
    // there are only here to get the sampler2Ds declared in the shader
    readonly property TextureInput sprite: TextureInput {
        texture: Texture {}
    }
    readonly property TextureInput glowSampler: TextureInput {
        texture: Texture {}
    }

    property real fadeAmount: 0.25  // 0 - 1
    property real blurQuality: 0.25 // 0.1 - 1.0

    Shader {
        id: vblurVert
        stage: Shader.Vertex
        shader: "qrc:/qtquick3deffects/shaders/motionblurvertical.vert"
    }
    Shader {
        id: vblurFrag
        stage: Shader.Fragment
        shader: "qrc:/qtquick3deffects/shaders/motionblurvertical.frag"
    }

    Shader {
        id: hblurVert
        stage: Shader.Vertex
        shader: "qrc:/qtquick3deffects/shaders/motionblurhorizontal.vert"
    }
    Shader {
        id: hblurFrag
        stage: Shader.Fragment
        shader: "qrc:/qtquick3deffects/shaders/motionblurhorizontal.frag"
    }

    Shader {
        id: blend
        stage: Shader.Fragment
        shader: "qrc:/qtquick3deffects/shaders/blend.frag"
    }

    Buffer {
        id: glowBuffer
        name: "glowBuffer"
        format: Buffer.RGBA8
        textureFilterOperation: Buffer.Nearest
        textureCoordOperation: Buffer.ClampToEdge
        bufferFlags: Buffer.SceneLifetime
        sizeMultiplier: effectRoot.blurQuality
    }

    Buffer {
        id: tempBuffer
        name: "tempBuffer"
        format: Buffer.RGBA8
        textureFilterOperation: Buffer.Linear
        textureCoordOperation: Buffer.ClampToEdge
        bufferFlags: Buffer.None
        sizeMultiplier: effectRoot.blurQuality
    }

    passes: [
        Pass {
            shaders: [ hblurVert, hblurFrag ]
            commands: [
                BufferInput {
                    // Expose the initially empty glowBuffer texture under the
                    // sampler2D glowSampler in the shader. Note the
                    // SceneLifetime and that the next pass writes to the same
                    // texture (accumulate).
                    sampler: "glowSampler"
                    buffer: glowBuffer
                }
            ]
            output: tempBuffer
        },
        Pass {
            shaders: [ vblurVert, vblurFrag ]
            commands: [
                // the texture for tempBuffer will be INPUT in this pass
                BufferInput {
                    buffer: tempBuffer
                }
            ]
            output: glowBuffer
        },
        Pass {
            shaders: [ blend ]
            commands: [
                // the texture for glowBuffer will be INPUT in this pass
                BufferInput {
                    buffer: glowBuffer
                },
                // the input texture (that would normally be INPUT) for this pass is exposed to the shader as sprite
                BufferInput {
                    sampler: "sprite"
                }
            ]
        }
    ]
}
