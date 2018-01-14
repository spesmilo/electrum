# ZCASH implementation: https://github.com/zcash/zcash/blob/master/qa/rpc-tests/test_framework/equihash.py
from pyblake2 import blake2b
from operator import itemgetter
import struct

DEBUG = False
VERBOSE = False


word_size = 32
word_mask = (1<<word_size)-1


def expand_array(inp, out_len, bit_len, byte_pad=0):
    assert bit_len >= 8 and word_size >= 7+bit_len
    bit_len_mask = (1<<bit_len)-1

    out_width = (bit_len+7)/8 + byte_pad
    assert out_len == 8*out_width*len(inp)/bit_len
    out = bytearray(out_len)

    bit_len_mask = (1 << bit_len) - 1

    # The acc_bits least-significant bits of acc_value represent a bit sequence
    # in big-endian order.
    acc_bits = 0
    acc_value = 0

    j = 0
    for i in range(len(inp)):
        acc_value = ((acc_value << 8) & word_mask) | inp[i]
        acc_bits += 8

        # When we have bit_len or more bits in the accumulator, write the next
        # output element.
        if acc_bits >= bit_len:
            acc_bits -= bit_len
            for x in range(byte_pad, out_width):
                out[j+x] = (
                    # Big-endian
                    acc_value >> (acc_bits+(8*(out_width-x-1)))
                ) & (
                    # Apply bit_len_mask across byte boundaries
                    (bit_len_mask >> (8*(out_width-x-1))) & 0xFF
                )
            j += out_width

    return out


def compress_array(inp, out_len, bit_len, byte_pad=0):
    assert bit_len >= 8 and word_size >= 7+bit_len

    in_width = (bit_len+7)/8 + byte_pad
    assert out_len == bit_len*len(inp)/(8*in_width)
    out = bytearray(out_len)

    bit_len_mask = (1 << bit_len) - 1

    # The acc_bits least-significant bits of acc_value represent a bit sequence
    # in big-endian order.
    acc_bits = 0;
    acc_value = 0;

    j = 0
    for i in range(out_len):
        # When we have fewer than 8 bits left in the accumulator, read the next
        # input element.
        if acc_bits < 8:
            acc_value = ((acc_value << bit_len) & word_mask) | inp[j]
            for x in range(byte_pad, in_width):
                acc_value = acc_value | (
                    (
                        # Apply bit_len_mask across byte boundaries
                        inp[j+x] & ((bit_len_mask >> (8*(in_width-x-1))) & 0xFF)
                    ) << (8*(in_width-x-1))); # Big-endian
            j += in_width
            acc_bits += bit_len

        acc_bits -= 8
        out[i] = (acc_value >> acc_bits) & 0xFF

    return out


def get_indices_from_minimal(minimal, bit_len):
    eh_index_size = 4
    assert (bit_len+7)/8 <= eh_index_size
    len_indices = 8*eh_index_size*len(minimal)/bit_len
    byte_pad = eh_index_size - (bit_len+7)/8
    expanded = expand_array(minimal, len_indices, bit_len, byte_pad)
    return [struct.unpack('>I', expanded[i:i+4])[0] for i in range(0, len_indices, eh_index_size)]


def get_minimal_from_indices(indices, bit_len):
    eh_index_size = 4
    assert (bit_len+7)/8 <= eh_index_size
    len_indices = len(indices)*eh_index_size
    min_len = bit_len*len_indices/(8*eh_index_size)
    byte_pad = eh_index_size - (bit_len+7)/8
    byte_indices = bytearray(''.join([struct.pack('>I', i) for i in indices]))
    return compress_array(byte_indices, min_len, bit_len, byte_pad)


def hash_nonce(digest, nonce):
    for i in range(8):
        digest.update(struct.pack('<I', nonce >> (32*i)))


def hash_xi(digest, xi):
    digest.update(struct.pack('<I', xi))
    return digest # For chaining


def count_zeroes(h):
    # Convert to binary string
    if type(h) == bytearray:
        h = ''.join('{0:08b}'.format(x, 'b') for x in h)
    else:
        h = ''.join('{0:08b}'.format(ord(x), 'b') for x in h)
    # Count leading zeroes
    return (h+'1').index('1')


def has_collision(ha, hb, i, l):
    res = [ha[j] == hb[j] for j in range((i-1)*l/8, i*l/8)]
    return reduce(lambda x, y: x and y, res)


def distinct_indices(a, b):
    for i in a:
        for j in b:
            if i == j:
                return False
    return True


def xor(ha, hb):
    return bytearray(a^b for a,b in zip(ha,hb))


def gbp_basic(digest, n, k):
    '''Implementation of Basic Wagner's algorithm for the GBP.'''
    validate_params(n, k)
    collision_length = n/(k+1)
    hash_length = (k+1)*((collision_length+7)//8)
    indices_per_hash_output = 512/n

    # 1) Generate first list
    if DEBUG: print('Generating first list')
    X = []
    tmp_hash = ''
    for i in range(0, 2**(collision_length+1)):
        r = i % indices_per_hash_output
        if r == 0:
            # X_i = H(I||V||x_i)
            curr_digest = digest.copy()
            hash_xi(curr_digest, i/indices_per_hash_output)
            tmp_hash = curr_digest.digest()
        X.append((
            expand_array(bytearray(tmp_hash[r*n/8:(r+1)*n/8]),
                         hash_length, collision_length),
            (i,)
        ))

    # 3) Repeat step 2 until 2n/(k+1) bits remain
    for i in range(1, k):
        if DEBUG: print('Round %d:' % i)

        # 2a) Sort the list
        if DEBUG: print('- Sorting list')
        X.sort(key=itemgetter(0))
        if DEBUG and VERBOSE:
            for Xi in X[-32:]:
                print('%s %s' % (print_hash(Xi[0]), Xi[1]))

        if DEBUG: print('- Finding collisions')
        Xc = []
        while len(X) > 0:
            # 2b) Find next set of unordered pairs with collisions on first n/(k+1) bits
            j = 1
            while j < len(X):
                if not has_collision(X[-1][0], X[-1-j][0], i, collision_length):
                    break
                j += 1

            # 2c) Store tuples (X_i ^ X_j, (i, j)) on the table
            for l in range(0, j-1):
                for m in range(l+1, j):
                    # Check that there are no duplicate indices in tuples i and j
                    if distinct_indices(X[-1-l][1], X[-1-m][1]):
                        if X[-1-l][1][0] < X[-1-m][1][0]:
                            concat = X[-1-l][1] + X[-1-m][1]
                        else:
                            concat = X[-1-m][1] + X[-1-l][1]
                        Xc.append((xor(X[-1-l][0], X[-1-m][0]), concat))

            # 2d) Drop this set
            while j > 0:
                X.pop(-1)
                j -= 1
        # 2e) Replace previous list with new list
        X = Xc

    # k+1) Find a collision on last 2n(k+1) bits
    if DEBUG:
        print('Final round:')
        print('- Sorting list')
    X.sort(key=itemgetter(0))
    if DEBUG and VERBOSE:
        for Xi in X[-32:]:
            print('%s %s' % (print_hash(Xi[0]), Xi[1]))
    if DEBUG: print('- Finding collisions')
    solns = []
    while len(X) > 0:
        j = 1
        while j < len(X):
            if not (has_collision(X[-1][0], X[-1-j][0], k, collision_length) and
                    has_collision(X[-1][0], X[-1-j][0], k+1, collision_length)):
                break
            j += 1

        for l in range(0, j-1):
            for m in range(l+1, j):
                res = xor(X[-1-l][0], X[-1-m][0])
                if count_zeroes(res) == 8*hash_length and distinct_indices(X[-1-l][1], X[-1-m][1]):
                    if DEBUG and VERBOSE:
                        print('Found solution:')
                        print('- %s %s' % (print_hash(X[-1-l][0]), X[-1-l][1]))
                        print('- %s %s' % (print_hash(X[-1-m][0]), X[-1-m][1]))
                    if X[-1-l][1][0] < X[-1-m][1][0]:
                        solns.append(list(X[-1-l][1] + X[-1-m][1]))
                    else:
                        solns.append(list(X[-1-m][1] + X[-1-l][1]))

        # 2d) Drop this set
        while j > 0:
            X.pop(-1)
            j -= 1
    return [get_minimal_from_indices(soln, collision_length+1) for soln in solns]


def gbp_validate(digest, minimal, n, k):
    validate_params(n, k)
    collision_length = n/(k+1)
    hash_length = (k+1)*((collision_length+7)//8)
    indices_per_hash_output = 512/n
    solution_width = (1 << k)*(collision_length+1)//8

    if len(minimal) != solution_width:
        print('Invalid solution length: %d (expected %d)' % \
            (len(minimal), solution_width))
        return False

    X = []
    for i in get_indices_from_minimal(minimal, collision_length+1):
        r = i % indices_per_hash_output
        # X_i = H(I||V||x_i)
        curr_digest = digest.copy()
        hash_xi(curr_digest, i/indices_per_hash_output)
        tmp_hash = curr_digest.digest()
        X.append((
            expand_array(bytearray(tmp_hash[r*n/8:(r+1)*n/8]),
                         hash_length, collision_length),
            (i,)
        ))

    for r in range(1, k+1):
        Xc = []
        for i in range(0, len(X), 2):
            if not has_collision(X[i][0], X[i+1][0], r, collision_length):
                print('Invalid solution: invalid collision length between StepRows')
                return False
            if X[i+1][1][0] < X[i][1][0]:
                print('Invalid solution: Index tree incorrectly ordered')
                return False
            if not distinct_indices(X[i][1], X[i+1][1]):
                print('Invalid solution: duplicate indices')
                return False
            Xc.append((xor(X[i][0], X[i+1][0]), X[i][1] + X[i+1][1]))
        X = Xc

    if len(X) != 1:
        print('Invalid solution: incorrect length after end of rounds: %d' % len(X))
        return False

    if count_zeroes(X[0][0]) != 8*hash_length:
        print('Invalid solution: incorrect number of zeroes: %d' % count_zeroes(X[0][0]))
        return False

    return True


def zcash_person(n, k):
    return b'ZcashPoW' + struct.pack('<II', n, k)


def print_hash(h):
    if type(h) == bytearray:
        return ''.join('{0:02x}'.format(x, 'x') for x in h)
    else:
        return ''.join('{0:02x}'.format(ord(x), 'x') for x in h)


def validate_params(n, k):
    if (k >= n):
        raise ValueError('n must be larger than k')
    if (((n/(k+1))+1) >= 32):
        raise ValueError('Parameters must satisfy n/(k+1)+1 < 32')


# a bit different from https://github.com/zcash/zcash/blob/master/qa/rpc-tests/test_framework/mininode.py#L747
# since electrum is a SPV oriented and not a node
def is_gbp_valid(nNonce, nSolution, n=48, k=5):
    # H(I||...
    digest = blake2b(digest_size=(512/n)*n/8, person=zcash_person(n, k))
    digest.update(super(CBlock, self).serialize()[:108])
    hash_nonce(digest, nNonce)
    if not gbp_validate(nSolution, digest, n, k):
        return False
    return True
