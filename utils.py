import binascii
import builtins

def _hex(b):
    if type(b) == list:
        ret = ""
        for c in b:
            ret += _hex(c)
        return ret
    elif type(b) == int:
        ret = builtins.hex(b)[2:]
        if len(ret) == 1:
            return "0" + ret
        return ret
    elif type(b) == str:
        return _hex(b.encode('ascii'))
    else:
        return binascii.hexlify(b).decode("ascii")

def hex(b):
    return _hex(b).upper()

# Returns the list of different indices
def compare(ref, faulted):
    ret = []
    for i in range(len(ref)):
        ref_b = ref[i]
        faulted_b = faulted[i]

        if ref_b != faulted_b:
            ret.append(i)

    return ret


def compare_bits(ref, faulted):
    ret = []

    for i in range(64):
        bit = 1 << i

        if ref & bit != faulted & bit:
            ret.append(i)

    return ret

def dump_diff(ref, faulted, diffs):
    print(f"Reference : {hex(ref)}")
    print(f"Faulted   : {hex(faulted)}")
    print(f"Difference: ", end="")

    diff_idx = 0
    for i in range(len(ref)):
        if diff_idx < len(diffs) and diffs[diff_idx] == i:
            diff_idx += 1
            print("--", end="")
        else:
            print("  ", end="")

    print()

    for d in diffs:
        print(f"  Byte {d:2} faulted: {hex(ref[d])} != {hex(faulted[d])}")


def xor(a, b):
    assert len(a) == len(b)

    ret = list(a)

    for i, x in enumerate(b):
        ret[i] ^= x

    return ret

def des_bytes(x):
    return x.to_bytes(8, byteorder='little')

def bits(x, sz):
    s = bin(x)[2:]
    return f"{s:0>{sz}}"

def extract(x, msb, lsb):
    return (x >> lsb) & ((1 << (msb - lsb + 1)) - 1)

def set_bit(x, idx):
    return x | (1 << idx)
