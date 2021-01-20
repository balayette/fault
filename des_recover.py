from utils import *
import collections
import des


# Find the sbox that the value will go through
def sbox_position(val):
    row = (extract(val, 5, 5) << 1) | extract(val, 0, 0)
    col = extract(val, 4, 1)

    return row, col


def is_solution(sbox_index, p, pos, faulted_pos):
    msb = 32 - sbox_index * 4
    row, col = pos
    row_faulted, col_faulted = faulted_pos

    a = extract(p, msb - 1, msb - 4)
    b = des.Sbox[sbox_index][row][col] ^ des.Sbox[sbox_index][row_faulted][col_faulted]

    return a == b


def recover_des_key(ref, faulted_outputs):
    # sbox_used[i] is the list of faults where the faulted bits went through
    # the ith sbox
    sbox_used = [[] for _ in range(8)]

    # fill up sbox_used
    for fault_index, fault in enumerate(faulted_outputs):
        diffs = compare(des_bytes(ref), des_bytes(fault))
        dump_diff(des_bytes(ref), des_bytes(fault), diffs)

        # We use the xor of the fault and the reference, because that allows
        # us to compute the permutation, extraction and expansion only once.
        # Any difference between the fault and the reference will show up as
        # a set bit after xor.
        # Without xor, we'd have to apply the transformations to both the
        # fault and the reference and compare them.
        x = fault ^ ref
        # invert the final permutation
        perm = des.permutation(x, des.IP, 64)
        # invert the swap
        perm = (perm >> 32) | ((perm & 0xFFFFFFFF) << 32)

        R15 = extract(perm, 63, 32)

        exp = des.expansion(R15)

        # bits go through the sbox 6 by 6 (8 blocks)
        # sbox[0] is used by the first block, starting from the MSB
        for i in range(8):
            msb = 48 - i * 6
            block = extract(exp, msb - 1, msb - 6)
            if block != 0:
                sbox_used[i].append(fault_index)

    KEY_SETS = [collections.Counter() for _ in range(8)]

    pref = des.permutation(ref, des.IP, 64)
    L16 = extract(pref, 63, 32)
    R15 = extract(pref, 31, 0)
    R15_expanded = des.expansion(R15)

    for sbox_index in range(8):
        print(f"Analysing sbox {sbox_index}")
        for fault_index in sbox_used[sbox_index]:
            fault = faulted_outputs[fault_index]
            pfault = des.permutation(fault, des.IP, 64)

            L16_faulted = extract(pfault, 63, 32)
            R15_faulted = extract(pfault, 31, 0)
            p = des.permutation(L16 ^ L16_faulted, des.Pinv, 32)

            R15_faulted_expanded = des.expansion(R15_faulted)

            for k in range(64):
                msb = 48 - sbox_index * 6

                chunk = extract(R15_expanded, msb - 1, msb - 6)
                chunk ^= k
                pos = sbox_position(chunk)

                chunk_faulted = extract(R15_faulted_expanded, msb - 1, msb - 6)
                chunk_faulted ^= k
                faulted_pos = sbox_position(chunk_faulted)

                if is_solution(sbox_index, p, pos, faulted_pos):
                    KEY_SETS[sbox_index][k] += 1

    # In theory, the most common value should be the correct value.
    # We could also choose the only value common to all guesses on an sbox,
    # but I like this better.
    key = 0
    for i in range(8):
        best = KEY_SETS[7 - i].most_common(1)[0][0]
        key |= best << (6 * i)

    return key


# Apply parity bits to a naked DES key
def apply_parity(k):
    for i in range(8):
        b = extract(k, 8 * (i + 1) - 1, 8 * i + 1)
        # about as fast as popcnt :)
        s = bin(b)[2:].count("1")
        if s % 2 == 0:
            k = set_bit(k, 8 * i)

    return k


# Given a vale in the range 0 <= guess <= 255, return a 64 bits (actually, the
# most significant bit that can be set is the 50th) bitmask, where the bits
# from `guess` where moved to match the missing bits indices needed to recover
# an initial DES key
def make_missing_bit_mask(guess):
    missing_bit_indices = [4, 6, 10, 13, 44, 45, 49, 50]

    mask = 0
    for i in range(8):
        mask |= (guess & (1 << i)) << (missing_bit_indices[i] - i)

    return mask


# We have 48 bits out of a 64 bits DES key.
# Luckily, DES keys are really only 56 bits large, because they include 8
# parity bits.
# We bruteforce the 8 missing bits that are not parity bits.
def recover_initial_des_key(k, clear, ref):
    base_key = des.permutation(des.permutation(k, des.PC2inv, 48), des.PC1inv, 56)

    for guess in range(256):
        candidate_k = base_key | make_missing_bit_mask(guess)

        # Applying the parity before encryption is not necessary, because the
        # bits are not used in DES.
        # We apply the parity after finding the correct key because the
        # user is likely to expect a key with parity bits.
        if ref == des.DES(clear, candidate_k):
            return apply_parity(candidate_k)

    return None
