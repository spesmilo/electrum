#
# fountain_utils.py
#
# Copyright © 2020 Foundation Devices, Inc.
# Licensed under the "BSD-2-Clause Plus Patent License"
#

from .random_sampler import RandomSampler
from .utils import int_to_bytes
from .xoshiro256 import Xoshiro256

# Fisher-Yates shuffle
def shuffled(items, rng):
    remaining = items
    result = []
    while len(remaining) > 0:
        index = rng.next_int(0, len(remaining) - 1)
        item = remaining.pop(index)
        result.append(item)

    return result

def choose_degree(seq_len, rng):
    degree_probabilities = []
    for i in range(1, seq_len + 1):
        degree_probabilities.append(1.0 / i)

    degree_chooser = RandomSampler(degree_probabilities)
    return degree_chooser.next(lambda: rng.next_double()) + 1

def choose_fragments(seq_num, seq_len, checksum):
    # The first `seq_len` parts are the "pure" fragments, not mixed with any
    # others. This means that if you only generate the first `seq_len` parts,
    # then you have all the parts you need to decode the message.
    if seq_num <= seq_len:
        return set([seq_num - 1])
    else:
        seed = int_to_bytes(seq_num) + int_to_bytes(checksum)
        rng = Xoshiro256.from_bytes(seed)
        degree = choose_degree(seq_len, rng)
        indexes = []

        for i in range(seq_len):
            indexes.append(i)
        shuffled_indexes = shuffled(indexes, rng)
        return set(shuffled_indexes[0:degree])

def contains(set_or_list, el):
    return el in set_or_list

def is_strict_subset(a, b):
    return a.issubset(b)

def set_difference(a, b):
    return a.difference(b)