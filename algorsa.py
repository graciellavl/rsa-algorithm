from email import message
import random
from sympy import *
import sympy.ntheory as nt
from typing import List
from textwrap import wrap

def fpb(a,b):
  if b == 0:
    return a
  else: 
    return fpb(b,a%b)

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
    gcd = fpb(e,phi)

    #e relatif prima dengan phi
    while (gcd!=1):
        e = random.randint(1, phi)
        gcd = fpb(e, phi)

    #invers modulo
    d = pow(e, -1, phi)

    #open file private and public
    fpri = open("private.txt", "r")
    fpub = open("public.txt", "r")

    #delete
    fpri.truncate(0)
    fpub.truncate(0)

    #replace key
    fpri.write((d,n))
    fpub.write((e,n))

    fpri.close()
    fpub.close()

    #public key, private key
    return ((e,n), (d,n))

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
    e, n = public_key

    block_size = len(str(n))

    m = text_to_block(plain, n)
    c = []

    for block in m:
        ci = pow(block, e, n)
        c.append(ci)
    return block_to_text(c, block_size)

def rsa_decrypt(cipher, private_key):
    d, n = private_key

    c = text_to_block(cipher, n)
    m = []
    for block in c:
        mi = pow(block, d, n)
        m.append(mi)
    # return block_to_text(m, block_size)
    return ''.join(list(map(str, m)))

if (__name__ == "__main__"):

    message = 9999999999999999999
    print("Message\t\t\t:", message)

    public_key, private_key = generatekey()
    ciphertext = rsa_encrypt(message, public_key)
    print("Ciphertext\t\t:", ciphertext)

    decrypted_m = rsa_decrypt(ciphertext, private_key)
    print("Decrypted\t\t:", decrypted_m)
