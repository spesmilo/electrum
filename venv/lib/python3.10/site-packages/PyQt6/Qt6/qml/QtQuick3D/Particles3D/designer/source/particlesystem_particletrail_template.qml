// Copyright (C) 2021 The Qt Company Ltd.
// SPDX-License-Identifier: LicenseRef-Qt-Commercial OR GPL-3.0-only

import QtQuick
import QtQuick3D
import QtQuick3D.Particles3D

ParticleSystem3D {
    id: particleTrailSystem
    TrailEmitter3D {
        id: trailEmitter
        follow: spriteParticle
        emitRate: 10
        particle: trailParticle
        velocity: trailDirection
        particleScale: 1
        VectorDirection3D {
            id: trailDirection
            direction.y: -1
            directionVariation.z: 10
            directionVariation.y: 10
            directionVariation.x: 10
        }
        SpriteParticle3D {
            id: trailParticle
        }
    }

    ParticleEmitter3D {
        id: spriteEmitter
        velocity: spriteDirection
        particle: spriteParticle
        lifeSpan: 2000
        particleScale: 2
        VectorDirection3D {
            id: spriteDirection
            directionVariation.z: 10
            directionVariation.y: 10
            directionVariation.x: 10
        }
        SpriteParticle3D {
            id: spriteParticle
            maxAmount: 1000
        }
        emitRate: 2
    }
}
