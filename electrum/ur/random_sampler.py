#
# random_sampler.py
#
# Copyright © 2020 Foundation Devices, Inc.
# Licensed under the "BSD-2-Clause Plus Patent License"
#

class RandomSampler:

    def __init__(self, probs):
        for p in probs:
            assert(p > 0)

        # Normalize given probabilities
        total = sum(probs)
        assert(total > 0)

        n = len(probs)

        P = []
        for p in probs:
            P.append((p * float(n)) / total)

        S = []
        L = []

        # Set separate index lists for small and large probabilities:
        for i in reversed(range(0, n)):
            # at variance from Schwarz, we reverse the index order
            if P[i] < 1:
                S.append(i)
            else:
                L.append(i)

        # Work through index lists
        _probs = [0] * n
        _aliases = [0] * n

        while len(S) > 0 and len(L) > 0:
            a = S.pop()  # Schwarz's l
            g = L.pop()  # Schwarz's g
            _probs[a] = P[a]
            _aliases[a] = g
            P[g] += P[a] - 1
            if P[g] < 1:
                S.append(g)
            else:
                L.append(g)

        while len(L) > 0:
            _probs[L.pop()] = 1

        while len(S) > 0:
            # can only happen through numeric instability
            _probs[S.pop()] = 1

        self.probs = _probs
        self.aliases = _aliases

    def next(self, rng_func):
        r1 = rng_func()
        r2 = rng_func()
        n = len(self.probs)
        i = int(float(n) * r1)
        return i if r2 < self.probs[i] else self.aliases[i]
