// Copyright (C) 2021 The Qt Company Ltd.
// SPDX-License-Identifier: LicenseRef-Qt-Commercial OR GPL-3.0-only

import QtQuick
import QtQuick3D
import QtQuick3D.Particles3D

ParticleSystem3D {
    id: modelBlendSystem
    Component {
        id: modelComponent
        Model {
            id: sphere
            source: "#Sphere"
            materials: defaultMaterial
            DefaultMaterial {
                id: defaultMaterial
                diffuseColor: "#4aee45"
            }
        }
    }

    Node {
        id: translateNode
        x: 150
    }
    ModelBlendParticle3D {
        id: modelBlendParticle
        modelBlendMode: ModelBlendParticle3D.Construct
        endNode: translateNode
        random: true
        delegate: modelComponent
        endTime: 1500
    }
    ParticleEmitter3D {
        id: emitter
        velocity: modelBlendDirection
        particle: modelBlendParticle
        lifeSpan: 4000
        emitRate: modelBlendParticle.maxAmount

        VectorDirection3D {
            id: modelBlendDirection
            directionVariation.z: 50
            directionVariation.x: 50
        }
    }
}
