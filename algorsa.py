from email import message
import random
from sympy import *
import sympy.ntheory as nt
from typing import List
from textwrap import wrap
from datetime import datetime
import timeit
import sys


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
    print(messages)
    return messages


def block_to_text(m: List[int], block_size: int):
    final_m = []
    print_format = "0" + str(block_size) + "d"
    for block in m:
        final_m.append(format(block, print_format))
    return "".join(final_m)


def rsa_encrypt(plain, public_key):
    start_time = timeit.default_timer()

    e, n = public_key

    block_size = len(str(n))

    m = text_to_block(plain, block_size)
    c = []

    for block in m:
        ci = pow(block, e, n)
        c.append(ci)

    stop_time = timeit.default_timer()
    execution_time = stop_time - start_time
    # (cipher, time)
    return (block_to_text(c, block_size), execution_time)


def rsa_decrypt(cipher, private_key):
    start_time = timeit.default_timer()

    d, n = private_key

    c = text_to_block(cipher, n)
    m = []
    for block in c:
        mi = pow(block, d, n)
        m.append(mi)

    stop_time = timeit.default_timer()
    execution_time = stop_time - start_time
    # (plain, time)
    return ((''.join(list(map(str, m)))), execution_time)


if (__name__ == "__main__"):

    # message = "9999999999999999999"
    # print("Message:", message)

    # public_key, private_key = generatekey()
    # ciphertext, time = rsa_encrypt(message, public_key)
    # print("Ciphertext:", ciphertext)
    # print("Time:", time)
    # print("Size:", sys.getsizeof(ciphertext))

    decrypted, exec_time = rsa_decrypt("000000000000000001412545429285629747403151003492215264193452250418464027403151003492215264450472047702038409065728986648370636450472047702038409162744740791221809153078800722807297193452250418464027403151003492215264000000000000000001229424900745236009153078800722807297065728986648370636412545429285629747000000000000000000065728986648370636193452250418464027193452250418464027450472047702038409000000000000000000162744740791221809412545429285629747153078800722807297000000000000000001", (255460846033287127, 530728801528365161))
    print("Decrypted:", decrypted)
    int_val_plaintext = int(decrypted)
    bytes_val = int_val_plaintext.to_bytes(10, 'big')
    plaintext = bytes_val.decode('utf-8')
    print("Time:", exec_time)
    print("Size:", sys.getsizeof(decrypted))

    print("size", sys.getsizeof(
        '035633971152406660044520212182232582234010342646019768278131440048215330000000000000000001177563904265596590035633971152406660'))
