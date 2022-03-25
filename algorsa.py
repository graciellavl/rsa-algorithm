from email import message
import random
from sympy import *
import sympy.ntheory as nt
from typing import List
from textwrap import wrap
from datetime import datetime
import timeit
import sys
import math

def fpb(a, b):
    if b == 0:
        return a
    else:
        return fpb(b, a % b)


def generateprime():
    while True:
        hasil = random.randint(0, 1000000000)
        if nt.isprime(hasil):
            return hasil


def generatekey():
    p = generateprime()
    q = generateprime()

    n = p*q
    phi = (p-1)*(q-1)
    e = random.randint(1, phi)
    gcd = fpb(e, phi)

    # e relatif prima dengan phi
    while (gcd != 1):
        e = random.randint(1, phi)
        gcd = fpb(e, phi)

    # invers modulo
    d = pow(e, -1, phi)

    # open file private and public
    fpri = open("key/id_rsa.pri", "w")
    fpub = open("key/id_rsa.pub", "w")

    # replace key
    fpri.write(str(d) + " " + str(n))
    fpub.write(str(e) + " " + str(n))

    fpri.close()
    fpub.close()

    # public key, private key
    return ((e, n), (d, n))


def text_to_block(message: str, n: int):
    digits: int = len(str(n))
    messages: List[int]
    try:
        messages = list(map(int, wrap(message, digits)))
        for block in messages:
            if (block >= n) or (block < 0):
                raise ValueError
    except:
        messages = list(map(int, wrap(message, digits - 1)))

    return messages


def block_to_text(m: List[int], block_size: int):
    final_m = []
    print_format = "0" + str(block_size) + "d"
    for block in m:
        final_m.append(format(block, print_format))
    return "".join(final_m)


def rsa_encrypt(plaintext, public_key):
    start_time = timeit.default_timer()
    e, n = public_key
    blocksize = math.ceil(math.log2(n)/8)
    
    plain_blocks = [b'\x00' + plaintext[i:i+blocksize-1]
                    for i in range(0, len(plaintext), blocksize-1)]

    pad_length = blocksize-len(plain_blocks[-1])
    if pad_length:
        plain_blocks[-1] = b'\x00' * pad_length + plain_blocks[-1]

    plain_blocks = [int.from_bytes(
        byte, byteorder='big', signed=False) for byte in plain_blocks]

    cipher_blocks = []
    for i in range(len(plain_blocks)):
        cipher_blocks.append(pow(plain_blocks[i], e, n))

    cipher_blocks = [block.to_bytes(
        length=blocksize, byteorder='big', signed=False) for block in cipher_blocks]

    ciphertext = b''
    for block in cipher_blocks:
        ciphertext += block
    ciphertext += pad_length.to_bytes(length=4, byteorder='big', signed=False)

    stop_time = timeit.default_timer()
    execution_time = stop_time - start_time
    # (cipher, time)
    return (bytearray(ciphertext), execution_time)


def rsa_decrypt(ciphertext, private_key):
    start_time = timeit.default_timer()

    d, n = private_key
    blocksize = math.ceil(math.log2(n)/8)

    # Splitting ciphertext with padding info
    cipher_blocks, padding = ciphertext[:-4], int.from_bytes(ciphertext[-4:],byteorder='big',signed=False)

    # Splitting blocks
    cipher_blocks = [cipher_blocks[i:i+blocksize] for i in range(0,len(cipher_blocks),blocksize)]

    # Converting blocks to integer
    cipher_blocks = [int.from_bytes(byte, byteorder='big', signed=False) for byte in cipher_blocks]


    # Decrypting
    plain_blocks = []
    for i in range(len(cipher_blocks)):
        plain_blocks.append(pow(cipher_blocks[i], d, n))
    
    # Converting blocks to Byte
    plain_blocks = [block.to_bytes(length=blocksize, byteorder='big',signed=False) for block in plain_blocks]

    # Removing padding
    plain_blocks[-1] = plain_blocks[-1][padding:]
    
    # Removing guard
    plain_blocks = [block[1:] for block in plain_blocks]

    # Generating plaintext
    plaintext = b''
    for block in plain_blocks:
        plaintext += block

    stop_time = timeit.default_timer()
    execution_time = stop_time - start_time
    # (plain, time)
    return (bytearray(plaintext), execution_time)


if (__name__ == "__main__"):

    print("size", sys.getsizeof(
        '035633971152406660044520212182232582234010342646019768278131440048215330000000000000000001177563904265596590035633971152406660'))
