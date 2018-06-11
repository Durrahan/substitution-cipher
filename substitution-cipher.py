#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import sys
import os
import argparse


def to_array(text):
    """Convert string to ascii array.
    
    Args:
        text: A string containing only uppercase and lowercase letters.
    Returns:
        A list of integers mapped to the corresponding ascii value. 
    
    """
    return [ord(x) - 96 for x in text.lower() if x >= "a" and x <= "z"]


def to_text(array):
    """Convert ascii array to string.
    
    Args:
        array: A list of integers mapped to the corresponding ascii value. 
    Returns:
        A string containing the corresponding lowercase letters from the ascii table. 
    
    """
    return "".join([chr(int(x) + 96) for x in array])


def encrypt(key, text):
    """Encrypt plaintext using a keyphrase.
    
    A substitution cipher with a keyphrase is used to encrypt a list of integers. 
    The keyphrase will be repeated if the text exceeds it's length.

    Args:
        key: A string representing the keyphrase. 
            Contains only uppercase and lowercase letters.
        text: A list of integers mapped to the corresponding ascii value. 
    Returns:
        A list of integers representing the encrypted text.
    
    """
    return [(text[x] + key[x % len(key)]) % 26 for x in range(len(text))]


def decrypt(key, cipher):
    """Decrypt cipher using a keyphrase.
    
    A substitution cipher with a keyphrase is used to decrypt a list of integers. 
    The keyphrase will be repeated if the text exceeds it's length.

    Args:
        key: A string representing the keyphrase. 
            Contains only uppercase and lowercase letters.
        cipher: A list of integers representing the encrypted text.
    Returns:
        A list of integers mapped to the corresponding ascii value. 
    
    """
    return [(int(cipher[x]) - key[x % len(key)]) % 26 for x in range(len(cipher))]


def main():
    parser = argparse.ArgumentParser(
        description="Encrypt or decrypt by using a substitution cipher.")
    parser.add_argument("key", metavar="key", nargs=1,
                        help="keyphrase")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("-d", "--decrypt", dest="to_decrypt", metavar="N", type=int, nargs="+",
                       choices=range(0, 26),
                       help="space seperated list of integers to be decrypted with the keyphrase. Allowed range is from 0 to 25.")
    group.add_argument("-e", "--encrypt", dest="to_encrypt", metavar="text", type=str, nargs=1,
                       help="plaintext to be encrypted using the keyphrase. Allowed are uppercase and lowercase letters.")

    args = parser.parse_args()
    if args.to_encrypt is not None:
        key = to_array("".join(args.key))
        text = to_array("".join(args.to_encrypt))
        print(encrypt(key, text))

    if args.to_decrypt is not None:
        key = to_array("".join(args.key))
        result = decrypt(key, args.to_decrypt)
        print(to_text(result))

    sys.exit(os.EX_USAGE)


if __name__ == "__main__":
    main()
