import random
from sympy import *
import sympy.ntheory as nt

def fpb(a,b):
    while (b!=0):
        a = b
        b = a%b
    return a

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

