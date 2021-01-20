#!/usr/bin/env python3

import binascii
import aes
import des
from aes_recover import recover_aes_key
from des_recover import recover_des_key, recover_initial_des_key
from utils import hex
import random
import sys
import struct
import argparse


def read_faults(fname, tr):
    output = []
    with open(fname, "r") as f:
        for l in f.readlines():
            output.append(tr(l.rstrip()))

    return output


def artificial_aes():
    PLAINTEXT = binascii.unhexlify("000102030405060708090a0b0c0d0e0f")
    KEY = binascii.unhexlify("bf05bd81f5497eef74dae9478eead746")

    print(f"Plaintext: {hex(PLAINTEXT)}")
    cipher = aes.AES(KEY)

    print("Round keys:")

    for i, mat in enumerate(cipher._key_matrices):
        print(f"[{i:02}]: {hex(mat)}")

    print("----")

    ref = cipher.encrypt_block(PLAINTEXT)
    print(f"ref: {hex(ref)}")

    outputs = []

    # 8 faults are enough in this super simple case
    for i in range(8):
        faulted = cipher.encrypt_block_with_fault(
            PLAINTEXT,
            i % 4,
            0,
            i,
        )
        outputs.append(faulted)
        print(f"{hex(faulted)}")

    k = recover_aes_key(ref, outputs)

    print(f"Recovered round 10 key: {hex(k)}")
    assert hex(k) == hex(cipher._key_matrices[-1])
    print(f"SUCCESS")


def real_aes(ref, faults):
    k = recover_aes_key(ref, faults)
    print(f"Recoved round 10 key: {hex(k)}")


def artificial_des():
    PLAINTEXT = 0x0102030405060708
    KEY = 0x1C8529CEA240AE4F

    ref = des.DES(PLAINTEXT, KEY)

    outputs = []

    for i in range(32):
        r = 15
        print(f"Faulting at round {r}")
        faulted = des.DES(PLAINTEXT, KEY, r, i % 32)
        outputs.append(faulted)

    k = recover_des_key(ref, outputs)

    subkeys = des.keySchedule(KEY)
    print(f"Recovered last round key: {hex(k)}")

    assert subkeys[-1] == k

    real_k = recover_initial_des_key(k, PLAINTEXT, ref)
    print(f"Real key: {hex(real_k)}")
    assert real_k == KEY


def real_des(plain, ref, faults):
    k = recover_des_key(ref, faults)
    print(f"Recovered round key: {hex(k)}")
    if plain:
        real_k = recover_initial_des_key(k, plain, ref)
        if real_k is None:
            print("Couldn't find the initial key")
        else:
            print(f"Real key: {hex(real_k)}")
    else:
        print("No plaintext supplied, can't recover the initial key (--plain)")


def main():
    parser = argparse.ArgumentParser(description="AES and DES fault analysis")

    parser.add_argument(
        "--aes", help="AES fault injection", default=False, action="store_true"
    )
    parser.add_argument(
        "--des", help="DES fault injection", default=False, action="store_true"
    )
    parser.add_argument(
        "--faults",
        help="File with one faulted output per line (hex)",
        type=str,
    )
    parser.add_argument(
        "--ref",
        help="Non faulted output for the plaintext (hex)",
        required=True,
        type=str,
    )
    parser.add_argument(
        "--plain",
        help="Plaintext that produces the reference output (hex)",
        type=str,
    )
    parser.add_argument(
        "--reverse",
        help="Reverse the key schedule from a final round key",
        default=False,
        action="store_true",
    )
    parser.add_argument(
        "--final-key", help="The final round key for --reverse", type=str
    )

    args = parser.parse_args()

    if not args.des and not args.aes:
        print("--des or --aes are required.")
        return
    if args.des and args.aes:
        print("Can't combine --aes and --des.")
        return
    if args.aes and args.reverse:
        print("AES key schedule reverse not supported")
        return
    if not args.reverse and not args.faults:
        print("--faults is required when not using --reverse")
        return
    if args.reverse:
        if not args.final_key:
            print("--reverse needs --final-key")
            return
        if args.des and not args.plain:
            print("DES --reverse needs --plaintext")
            return

    if args.reverse:
        if args.des:
            plain = int(args.plain, 16)
            k = int(args.final_key, 16)
            ref = int(args.ref, 16)
            init_k = recover_initial_des_key(k, plain, ref)
            if init_k is not None:
                print(f"Round 0 DES key: {hex(init_k)}")
            else:
                print("Couldn't find a matching DES round 0 key")
    elif args.aes:
        faults = read_faults(args.faults, lambda x: binascii.unhexlify(x))
        ref = binascii.unhexlify(args.ref)
        real_aes(ref, faults)
    else:
        faults = read_faults(args.faults, lambda x: int(x, 16))
        ref = int(args.ref, 16)
        plain = int(args.plain, 16) if args.plain else None
        real_des(plain, ref, faults)


if __name__ == "__main__":
    main()
