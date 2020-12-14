#!/usr/bin/env python3

import argparse
import collections
import itertools
import os
import binascii
import builtins
import random
import aes

PLAINTEXT = binascii.unhexlify("000102030405060708090a0b0c0d0e0f")
KEY = binascii.unhexlify("bf05bd81f5497eef74dae9478eead746")

# FAULT_PATTERNS[idx] is the fault pattern that appears when a byte of the
# state column idx is faulted.
FAULT_PATTERNS = [
    [0, 7, 10, 13],
    [1, 4, 11, 14],
    [2, 5, 8, 15],
    [3, 6, 9, 12],
]

# The index where the faulted byte ends up after mixing
FAULT_DESTINATION = [
    [0, 13, 10, 7],
    [4, 1, 14, 11],
    [8, 5, 2, 15],
    [12, 9, 6, 3],
]

# The only things that matter are the value of the fault and the row of the
# fault.
# The column does not change the way the fault propagates (MixColumns mixes all
# columns independently).
# This is a pure function, and the list could be inlined.
def compute_propagation():
    ret = []

    for row in range(4):
        for fault in range(256):
            col = [0 if x != row else fault for x in range(4)]
            aes.mix_single_column(col)

            ret.append(col)

    return ret


# Each value in FAULT_PROPAGATION is the difference introduced by a different
# (faulted_row, fault_value) pair.
FAULT_PROPAGATION = compute_propagation()


class Fault:
    def __init__(self, output, column):
        self.output = output
        self.column = column


def hex(b):
    if type(b) == list:
        ret = ""
        for c in b:
            ret += hex(c)
        return ret
    elif type(b) == int:
        ret = builtins.hex(b)[2:]
        if len(ret) == 1:
            return "0" + ret
        return ret
    elif type(b) == Fault:
        return hex(b.output)
    else:
        return binascii.hexlify(b).decode("ascii")


# Returns the list of different indices
def compare(ref, faulted):
    ret = []
    for i in range(16):
        ref_b = ref[i : i + 1]
        faulted_b = faulted[i : i + 1]

        if ref_b != faulted_b:
            ret.append(i)

    return ret


def dump_diff(ref, faulted, diffs):
    print(f"Reference : {hex(ref)}")
    print(f"Faulted   : {hex(faulted)}")
    print(f"Difference: ", end="")

    diff_idx = 0
    for i in range(16):
        if diff_idx < len(diffs) and diffs[diff_idx] == i:
            diff_idx += 1
            print("--", end="")
        else:
            print("  ", end="")

    print()

    for d in diffs:
        print(f"  Byte {d:2} faulted: {hex(ref[d])} != {hex(faulted[d])}")


def recognize_fault_pattern(diff):
    if len(diff) != 4:
        return None

    assert diff in FAULT_PATTERNS

    return FAULT_PATTERNS.index(diff)


# Return all values of k such that the difference of values after partial
# decryption of the reference byte and of the faulted byte equals d
def compute_key_candidates(ref_b, out_b, d):
    cands = []

    for k in range(256):
        if aes.inv_s_box[ref_b ^ k] ^ aes.inv_s_box[out_b ^ k] == d:
            cands.append(k)

    return cands


def recover_key(ref, faults):
    # There are 4 subkeys
    KEY_SETS = [collections.Counter() for _ in range(4)]

    for fault in faults:
        print(f"Analyzing {hex(fault.output)}")
        key_indices = list(FAULT_DESTINATION[fault.column])

        # We don't know what row was faulted, and we don't know what value
        # was faulted, so we have to go over everything.
        for D in FAULT_PROPAGATION:
            candidates = []

            # Check if D may be the fault that was introduced.
            # There must be key candidates for all 4 bytes.
            for i in range(4):
                key_index = key_indices[i]
                c = compute_key_candidates(
                    ref[key_index], fault.output[key_index], D[i]
                )
                if len(c) == 0:
                    break

                candidates.append(c)

            # If we have candidates for all 4 bytes, register them.
            # There may be multiple candidates for each byte, so go over
            # all 4-tuples of candidates and register them all.
            if len(candidates) == 4:
                for k in itertools.product(*candidates):
                    KEY_SETS[fault.column][k] += 1

    # We have analysed all the faults, it is now highly likely that the most
    # common 4-tuple of each fault pattern is the correct key.
    key = [0] * 16

    for pattern_idx in range(len(FAULT_DESTINATION)):
        most_common = KEY_SETS[pattern_idx].most_common(1)[0][0]
        for i, key_index in enumerate(FAULT_DESTINATION[pattern_idx]):
            key[key_index] = most_common[i]

    return key


def do(K):
    print(f"Plaintext: {hex(PLAINTEXT)}")
    cipher = aes.AES(K)

    print("Round keys:")

    for i, mat in enumerate(cipher._key_matrices):
        print(f"[{i:02}]: {hex(mat)}")

    print("----")

    ref = cipher.encrypt_block(PLAINTEXT)

    faults = []

    # 8 faults are enough in this super simple case
    for i in range(8):
        faulted = cipher.encrypt_block_with_fault(
            PLAINTEXT,
            i % 4,
            0,
            i,
        )
        diffs = compare(ref, faulted)
        if len(diffs) == 0:
            continue

        column_idx = recognize_fault_pattern(diffs)
        if column_idx is None:
            continue

        dump_diff(ref, faulted, diffs)

        faults.append(Fault(faulted, column_idx))

    k = recover_key(ref, faults)

    print(f"Recovered round 10 key: {hex(k)}")
    assert hex(k) == hex(cipher._key_matrices[-1])
    print(f"SUCCESS")


if __name__ == "__main__":
    do(KEY)