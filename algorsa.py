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
    d = pow(e, -1, phi(n))

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

def pow_mod(x: int, y: int, p: int) -> int:
    """
    Count (x ** y) % p using divide and conquer.
    x > 0
    """
    assert x >= 0
    x = x % p

    if x == 0: return 0
    if y == 0: return 1
    if y == 1: return x

    temp: int = pow_mod(x, y // 2, p)
    return (temp * temp * pow_mod(x, y % 2, p)) % p

def inverse_modulo(a: int, m: int) -> int:
    """
    Count (1 / a) % m using bezout identity.
    @documentation https://www.dcode.fr/bezout-identity
    """
    assert fpb(a, m) == 1

    r = a; r_ = m
    u = 1; u_ = 0
    v = 0; v_ = 1
    while r_ != 0:
        q = r // r_
        r_temp = r;             u_temp = u;             v_temp = v
        r = r_;                 u = u_;                 v = v_
        r_ = r_temp - (q * r_); u_ = u_temp - (q * u_); v_ = v_temp - (q * v_)
    
    # if u is negative, u becomes positive.
    return u % m

def rsa_encrypt(plain, public_key):
    e, n = public_key

    block_size = len(str(n))

    m = text_to_block(plain, n)
    c = []

    for block in m:
        ci = pow_mod(block, e, n)
        c.append(ci)
    return block_to_text(c, block_size)

def rsa_decrypt(cipher, private_key):
    d, n = private_key

    c = text_to_block(cipher, n)
    m = []
    for block in c:
        mi = pow_mod(block, d, n)
        m.append(mi)
    # return block_to_text(m, block_size)
    return ''.join(list(map(str, m)))

if (__name__ == "__main__"):
    # p = int(input("Nilai p: "))
    # q = int(input("Nilai q: "))
    p = generateprime()
    q = generateprime()
    n = p * q
    toi = (p - 1) * (q - 1)
    e = generateprime()

    # e = int(input("Nilai e: "))
    d = inverse_modulo(e, toi)
    print("Nilai p dan q\t\t:", p, ",", q)
    print("Nilai n dan toi\t\t:", n, ",", toi)
    print("Public key (e, n)\t:", e, ",", n)
    print("Private key (d, n)\t:", d, ",", n)

    # message = "7041111140011080204"
    message = "99999999999999999999"
    # message = input()
    print("Message\t\t\t:", message)

    ciphertext = rsa_encrypt(message, n, e)
    print("Ciphertext\t\t:", ciphertext)

    decrypted_m = rsa_decrypt(ciphertext, n, d)
    print("Decrypted\t\t:", decrypted_m)
