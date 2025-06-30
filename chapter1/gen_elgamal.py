#!/usr/bin/python3
# python3-pycryptodome
from Cryptodome.PublicKey import ElGamal
from Cryptodome.Random import get_random_bytes
k = ElGamal.generate(256, randfunc=get_random_bytes)

print('p', hex(k.p))
print('g', hex(k.g))
print('x', hex(k.x))
print('y', hex(k.y))
