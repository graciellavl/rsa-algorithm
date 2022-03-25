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
        mi = mi.to_bytes(len(str(mi)), 'big')
        mi = mi.replace(b'\x00',b'')
        m.append(mi)

    #m = str(m)
    #m = m.replace(b'\x00',b'')

    stop_time = timeit.default_timer()
    execution_time = stop_time - start_time
    # (plain, time)
    return (m, execution_time)


if (__name__ == "__main__"):

    # message = "9999999999999999999"
    # print("Message:", message)

    # public_key, private_key = generatekey()
    # ciphertext, time = rsa_encrypt(message, public_key)
    # print("Ciphertext:", ciphertext)
    # print("Time:", time)
    # print("Size:", sys.getsizeof(ciphertext))

    decrypted, exec_time = rsa_decrypt("118706122502634873118981311662182950413359720199452371689562180737007949024557434041394393292491689895759117948843250721017466624801994523716895621807370079490245574340413940996151254699501744055434069074821366745150027162389914627266967054331356502400700701309961512546995017440554340690748213667451501821283595711692888389051878508431396005357166793580259136164583615477960520798267858439329249168989575911794884325072101746662480199452371689562180737007949024557434041394000000000000000000000000000000000000000000105953986760353610432796280021890979626290111667935802591361645836154779605207982678584027162389914627266967054331356502400700701318706122502634873118981311662182950413359720000000000000000000000000000000000000000000027162389914627266967054331356502400700701339329249168989575911794884325072101746662483932924916898957591179488432507210174666248099615125469950174405543406907482136674515000000000000000000000000000000000000000000001821283595711692888389051878508431396005357187061225026348731189813116621829504133597216679358025913616458361547796052079826785840000000000000000000000000000000000000000001", (255460846033287127, 530728801528365161))
    print("Decrypted:", decrypted)
    #int_val_plaintext = int(decrypted)
   # bytes_val = int_val_plaintext.to_bytes(len("118706122502634873118981311662182950413359720199452371689562180737007949024557434041394393292491689895759117948843250721017466624801994523716895621807370079490245574340413940996151254699501744055434069074821366745150027162389914627266967054331356502400700701309961512546995017440554340690748213667451501821283595711692888389051878508431396005357166793580259136164583615477960520798267858439329249168989575911794884325072101746662480199452371689562180737007949024557434041394000000000000000000000000000000000000000000105953986760353610432796280021890979626290111667935802591361645836154779605207982678584027162389914627266967054331356502400700701318706122502634873118981311662182950413359720000000000000000000000000000000000000000000027162389914627266967054331356502400700701339329249168989575911794884325072101746662483932924916898957591179488432507210174666248099615125469950174405543406907482136674515000000000000000000000000000000000000000000001821283595711692888389051878508431396005357187061225026348731189813116621829504133597216679358025913616458361547796052079826785840000000000000000000000000000000000000000001"), 'big')
   # plaintext = bytes_val.decode('latin')
   # print('Plaintext: ', plaintext)
    print("Time:", exec_time)
    print("Size:", sys.getsizeof(decrypted))

    print("size", sys.getsizeof(
        '035633971152406660044520212182232582234010342646019768278131440048215330000000000000000001177563904265596590035633971152406660'))
