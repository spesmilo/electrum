// Copyright (C) 2021 The Qt Company Ltd.
// SPDX-License-Identifier: LicenseRef-Qt-Commercial OR GPL-3.0-only

import QtQuick
import QtQuick3D
import QtQuick3D.Particles3D

ParticleSystem3D {
    id: attractorSystem
    ParticleEmitter3D {
        velocity: attractorDirection
        particle: attractorParticle
        emitRate: 200
        lifeSpan: 2000

        SpriteParticle3D {
            id: attractorParticle
            maxAmount: 1000
        }

        VectorDirection3D {
            id: attractorDirection
            direction.y: 40
            directionVariation.y: 10
            directionVariation.z: 100
            directionVariation.x: 100
        }
    }

    Attractor3D {
        id: particleAttractor
        y: 100
        duration: 1000
        particles: attractorParticle
    }
}
