// Copyright (C) 2021 The Qt Company Ltd.
// SPDX-License-Identifier: LicenseRef-Qt-Commercial OR GPL-3.0-only

import QtQuick
import QtQuick3D
import QtQuick3D.Particles3D

ParticleSystem3D {
    id: dust
    y: 100
    ParticleEmitter3D {
        id: dustEmitter
        emitRate: 20
        particle: dustParticle
        particleScaleVariation: 0.25
        particleScale: 0.75
        lifeSpan: 10000
        lifeSpanVariation: 100
        velocity: dustDirection
        shape: dustShape
        SpriteParticle3D {
            id: dustParticle
            color: "#6ed0d0d0"
            sprite: dustTexture
            billboard: true
            maxAmount: 500
            fadeInDuration: 1500
            fadeOutDuration: 1500
            VectorDirection3D {
                id: dustDirection
                direction.y: 2
                direction.z: 0
                directionVariation.x: 2
                directionVariation.y: 2
                directionVariation.z: 2
            }

            Texture {
                id: dustTexture
                source: "sphere.png"
            }
        }
    }

    ParticleShape3D {
        id: dustShape
        extents.x: 500
        extents.y: 200
        extents.z: 500
    }

    Wander3D {
        id: dustWander
        system: dust
        particles: dustParticle
        uniquePaceVariation: 0.5
        uniqueAmountVariation: 0.5
        uniquePace.x: 0.05
        uniquePace.z: 0.05
        uniquePace.y: 0.05
        uniqueAmount.x: 10
        uniqueAmount.z: 10
        uniqueAmount.y: 10
    }
}
