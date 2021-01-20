#!/usr/bin/python3

import argparse
import binascii
import aes
import des
from utils import hex


def main():
    parser = argparse.ArgumentParser(description="Simple encryption")

    parser.add_argument(
        "--aes", help="AES encryption", default=False, action="store_true"
    )
    parser.add_argument(
        "--des", help="DES encryption", default=False, action="store_true"
    )

    parser.add_argument("--key", help="Encryption key (hex)", type=str, required=True)
    parser.add_argument("--plaintext", help="Plaintext (hex)", type=str)
    parser.add_argument("--plaintext-file", help="File of plaintexts (hex)", type=str)

    args = parser.parse_args()

    if not args.des and not args.aes:
        print("--des or --aes are required.")
        return
    if args.des and args.aes:
        print("Can't combine --aes and --des.")
        return
    if not args.plaintext and not args.plaintext_file:
        print("Need --plaintext or --plaintext-file")
        return


    tr = lambda x: binascii.unhexlify(x) if args.aes else int(x, 16)
    k = tr(args.key)

    if args.aes:
        aes_cipher = aes.AES(k)

    if args.plaintext:
        p = tr(args.plaintext)
        if args.aes:
            print(f"{hex(aes_cipher.encrypt_block(p))}")
        else:
            print(f"{hex(des.DES(p, k))}")

    if args.plaintext_file:
        with open(args.plaintext_file, "r") as f:
            for line in f.readlines():
                p = tr(line.rstrip())
                if args.aes:
                    print(f"{hex(aes_cipher.encrypt_block(p))}")
                else:
                    print(f"{hex(des.DES(p, k))}")


if __name__ == "__main__":
    main()
