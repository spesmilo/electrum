// Copyright (C) 2021 The Qt Company Ltd.
// SPDX-License-Identifier: LicenseRef-Qt-Commercial OR GPL-3.0-only

import QtQuick
import QtQuick3D
import QtQuick3D.Particles3D

ParticleSystem3D {
    id: rainMist
    ParticleEmitter3D {
        id: rainMistEmitter
        depthBias: -20
        lifeSpan: 1200
        particleScale: 5
        particle: rainMistParticle
        particleEndScale: 20
        lifeSpanVariation: 300
        velocity: rainMistDirection
        particleScaleVariation: 5
        emitRate: 30

        SpriteParticle3D {
            id: rainMistParticle
            color: "#c5e3eaf2"
            maxAmount: 100
            particleScale: 12
            sprite: rainMistTexture
            spriteSequence: rainMistSequence
            fadeInDuration: 200
            fadeOutDuration: 350
            fadeInEffect: Particle3D.FadeOpacity
            blendMode: SpriteParticle3D.SourceOver
            sortMode: Particle3D.SortNewest
            billboard: true

            Texture {
                id: rainMistTexture
                source: "smoke2.png"
            }

            SpriteSequence3D {
                id: rainMistSequence
                duration: 2000
                frameCount: 15
            }

            VectorDirection3D {
                id: rainMistDirection
                direction.x: 500
                direction.y: 0
                directionVariation.x: 100
                directionVariation.y: 2
                directionVariation.z: 100
            }

            Wander3D {
                id: rainMistWander
                uniqueAmountVariation: 1
                uniquePaceVariation: 1
                fadeInDuration: 500
                uniqueAmount.y: 10
                uniquePace.y: 0.3
                fadeOutDuration: 200
                particles: rainMistParticle
                system: rainMist
            }
        }
    }
}
