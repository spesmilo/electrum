// Copyright (C) 2021 The Qt Company Ltd.
// SPDX-License-Identifier: LicenseRef-Qt-Commercial OR GPL-3.0-only

import QtQuick
import QtQuick3D
import QtQuick3D.Particles3D

ParticleSystem3D {
    id: animatedSpriteSystem
    ParticleEmitter3D {
        id: animatedSpriteEmitter
        velocity: animatedSpriteDirection
        particle: animatedSpriteParticle
        lifeSpan: 1000
        emitRate: 1
        SpriteParticle3D {
            id: animatedSpriteParticle
            particleScale: 25
            billboard: true
            sprite: animatedTexture
            spriteSequence: animatedSequence
            maxAmount: 10

            SpriteSequence3D {
                id: animatedSequence
                duration: -1
                interpolate: false
            }

            Texture {
                id: animatedTexture
            }
        }

        VectorDirection3D {
            id: animatedSpriteDirection
        }
    }
}
