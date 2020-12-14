#!/usr/bin/env python3

import binascii
import aes
import des
from aes_recover import recover_aes_key
from des_recover import recover_des_key
from utils import hex

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

    k = recover_aes_key(ref, outputs)

    print(f"Recovered round 10 key: {hex(k)}")
    assert hex(k) == hex(cipher._key_matrices[-1])
    print(f"SUCCESS")

def artificial_des():
    PLAINTEXT = 0x0001020304050607
    KEY = 0xbf05bd81f5497eef

    ref = des.DES(PLAINTEXT, KEY)

    outputs = []

    for i in range(100):
        faulted = des.DES(PLAINTEXT, KEY, 15, i % 32)
        outputs.append(faulted)

    k = recover_des_key(ref, outputs)

    print(f"Recovered key: {hex(k)}")

if __name__ == "__main__":
    artificial_des()
