// Copyright (C) 2021 The Qt Company Ltd.
// SPDX-License-Identifier: LicenseRef-Qt-Commercial OR GPL-3.0-only

import QtQuick
import QtQuick3D
import QtQuick3D.Particles3D

ParticleSystem3D {
    id: exhaust
    ParticleEmitter3D {
        id: exhaustEmitter
        emitRate: 35
        lifeSpan: 300
        particle: exhaustParticle
        particleScale: 8
        particleScaleVariation: 3
        lifeSpanVariation: 100
        velocity: exhaustDirection
        depthBias: -20
        SpriteParticle3D {
            id: exhaustParticle
            color: "#fdfeff"
            maxAmount: 100
            particleScale: 12
            fadeOutDuration: 150
            fadeInDuration: 150
            fadeInEffect: Particle3D.FadeScale
            blendMode: SpriteParticle3D.SourceOver
            sortMode: Particle3D.SortNewest
            spriteSequence: exhaustSequence
            sprite: exhaustTexture
            billboard: true
            Texture {
                id: exhaustTexture
                source: "smoke2.png"
            }

            SpriteSequence3D {
                id: exhaustSequence
                frameCount: 15
                duration: 2000
            }

            Wander3D {
                id: exhaustWander
                fadeInDuration: 500
                particles: exhaustParticle
                system: exhaust
                globalPace.y: 0.3
                globalAmount.y: 50
                uniquePaceVariation: 0.3
                uniqueAmountVariation: 0.3
                uniquePace.x: 0.1
                uniquePace.y: 0.3
                uniquePace.z: 0.25
                uniqueAmount.x: 30
                uniqueAmount.y: 60
                uniqueAmount.z: 50
            }

            VectorDirection3D {
                id: exhaustDirection
                directionVariation.x: 5
                directionVariation.y: 10
                directionVariation.z: 20
                direction.x: 750
                direction.y: 0
            }
        }
    }
}
