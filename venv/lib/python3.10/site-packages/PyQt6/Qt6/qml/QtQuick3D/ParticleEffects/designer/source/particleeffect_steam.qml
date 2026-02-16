// Copyright (C) 2021 The Qt Company Ltd.
// SPDX-License-Identifier: LicenseRef-Qt-Commercial OR GPL-3.0-only

import QtQuick
import QtQuick3D
import QtQuick3D.Particles3D

ParticleSystem3D {
    id: steam
    ParticleEmitter3D {
        id: steamEmitter
        emitRate: 10
        lifeSpan: 1500
        lifeSpanVariation: 300
        particle: steamParticle
        particleScale: 7.5
        particleEndScale: 12.5
        particleScaleVariation: 2.5
        velocity: steamDirection
        depthBias: -100

        SpriteParticle3D {
            id: steamParticle
            color: "#c5e3eaf2"
            maxAmount: 50
            particleScale: 12
            fadeInDuration: 200
            fadeOutDuration: 350
            sprite: steamTexture
            spriteSequence: steamSequence
            fadeInEffect: Particle3D.FadeOpacity
            blendMode: SpriteParticle3D.SourceOver
            sortMode: Particle3D.SortNewest
            billboard: true

            Texture {
                id: steamTexture
                source: "smoke2.png"
            }

            SpriteSequence3D {
                id: steamSequence
                duration: 2000
                frameCount: 15
            }

            VectorDirection3D {
                id: steamDirection
                direction.y: 150
                directionVariation.x: 50
                directionVariation.y: 10
                directionVariation.z: 50
            }

            Wander3D {
                id: steamWander
                uniquePace.y: 0.03
                uniqueAmount.y: 20
                uniquePaceVariation: 1
                uniqueAmountVariation: 1
                fadeInDuration: 300
                fadeOutDuration: 500
                particles: steamParticle
                system: steam
            }
        }
    }
}
