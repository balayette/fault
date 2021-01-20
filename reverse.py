#!/usr/bin/python3

import argparse
from des_recover import recover_initial_des_key
from utils import hex


def main():
    parser = argparse.ArgumentParser(description="DES key schedule reverser")

    parser.add_argument(
        "--plain",
        help="Plaintext that produces the reference output (hex)",
        type=str,
        required=True,
    )
    parser.add_argument(
        "--ref",
        help="Output for the plaintext (hex)",
        required=True,
        type=str,
    )
    parser.add_argument(
        "--final-key", help="The final round key", type=str, required=True
    )

    args = parser.parse_args()

    plain = int(args.plain, 16)
    k = int(args.final_key, 16)
    ref = int(args.ref, 16)
    init_k = recover_initial_des_key(k, plain, ref)
    if init_k is not None:
        print(f"Round 0 DES key: {hex(init_k)}")
    else:
        print("Couldn't find a matching DES round 0 key")

if __name__ == "__main__":
    main()
