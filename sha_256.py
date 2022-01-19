# -*- coding: utf-8 -*-
"""
Created on Fri Jan 14 14:11:21 2022

@author: CLowe
"""

### SHA-256 Algorithm Implementation
# Much of this is a playground indebted to Paulo Doms

import math

#%%

# Functions
def translate(message):
    charcodes = [ord(c) for c in message]
    bytes_ = []
    for char in charcodes:
        bytes_.append(bin(char)[2:].zfill(8))
    bits = []
    for byte in bytes_:
        for bit in byte:
            bits.append(int(bit))
    return bits

def b2_to_b16(value):
    value = ''.join(str(x) for x in value)
    binaries = []
    for d in range(0, len(value), 4):
        binaries.append('0b' + value[d:d+4])
    hexes = ''
    for b in binaries:
        hexes += hex(int(b,2))[2:]
    return hexes

def fillZeros(bits, length=8, endian='LE'):
    l = len(bits)
    if endian == 'LE':
        for i in range(l, length):
            bits.append(0)
    else:
        while l < length:
            bits.insert(0, 0)
            l = len(bits)
    return bits

def chunker(bits, byte_length=8):
    chunked = []
    for b in range(0, len(bits), byte_length):
        chunked.append(bits[b:b+byte_length])
    return chunked

def initializer(values):
    binaries = [bin(int(v,16))[2:] for v in values]
    words = []
    for binary in binaries:
        word = []
        for b in binary:
            word.append(int(b))
        words.append(fillZeros(word,32,'BE'))
    return words

def preprocessMessage(message):
    bits = translate(message)
    length = len(bits)
    message_len = [int(b) for b in bin(length)[2:].zfill(64)]
    if length < 448:
        bits.append(1)
        bits = fillZeros(bits, 448, 'LE')
        bits = bits + message_len
        return [bits]
    elif length == 448:
        bits.append(1)
        bits = fillZeros(bits, 1024, 'LE')
        bits[-64:] = message_len
        return chunker(bits, 512)
    else:
        bits.append(1)
        while len(bits) % 512 != 0:
            bits.append(0)
        bits[-64:] = message_len
        return chunker(bits, 512)
    
# utility functions
def isTrue(x): return x == 1

def if_(i,y,z): return y if isTrue(i) else z

def and_(i,j): return if_(i,j,0)
def AND_(i,j): return [and_(ia,ja) for ia,ja in zip(i,j)]

def not_(i): return if_(i,0,1)
def NOT_(i): return [not_(x) for x in i]

def xor_(i,j): return if_(i,not_(j),j)
def XOR_(i,j): return [xor_(ia,ja) for ia,ja in zip(i,j)]

def xorxor_(i,j,l): return xor_(i,xor_(j,l))
def XORXOR_(i,j,l): return [xorxor_(ia,ja,la) for ia,ja,la in zip(i,j,l)]

def maj_(i,j,k): return max([i,j,], key=[i,j,k].count)

# shift/rotation functions
def rotr(x,n): return x[-n:] + x[:-n]
def shir(x,n): return n*[0] + x[:-n]

# binary adder
def add(i,j):
    length = len(i)
    sums = list(range(length))
    c = 0
    for x in range(length-1,-1,-1):
        sums[x] = xorxor_(i[x], j[x], c)
        c = maj_(i[x], j[x], c)
    return sums

#%%

# Calculate initially defined hashing values
def get_constants():
    prime_nums = [2]
    num = 3
    while len(prime_nums) < 64:
        for x in range(2, num):
            if (num % x) == 0:
                break
        else:
            prime_nums.append(num)
        num = num+1
                
    h_inits = []
    for num in prime_nums[:8]:
        s_root = num**(1./2)
        fractions = math.modf(s_root)[0]
        as_hex = hex(int(fractions * (2**32)))
        h_inits.append(as_hex)
    k_inits = []
    for num in prime_nums:
        c_root = num**(1./3)
        fractions = math.modf(c_root)[0]
        as_hex = hex(int(fractions * (2**32)))
        k_inits.append(as_hex)
    return h_inits, k_inits

h_inits, k_inits = get_constants()

h0, h1, h2, h3, h4, h5, h6, h7 = initializer(h_inits)
k = initializer(k_inits)

#%%

# Readouts
init_str = 'XO'
print('***Initial string is: \n{}\n'.format(init_str))
print(' - Translation to binary is: \n{}\n'.format(translate(init_str)))
print(' - Encoding to hex is: \n{}\n'.format(b2_to_b16(translate(init_str))))
print(' - PreProcessing results in: \n{}\n'.format(preprocessMessage(init_str)))
print(' - Shape of preprocessing: {}'.format(np.shape(preprocessMessage(init_str))))
    
#%%

# Algorithm steps
message = 'portsmouth'
chunks = preprocessMessage(message)
for chunk in chunks:
    w = chunker(chunk,32)
    for _ in range(48):
        w.append(32*[0])
#%%

# Calculate new words (via rotation and shifts), calculate sigmas using bitwise XOR
for i in range(16,64):
    s0 = XORXOR_(rotr(w[i-15],7), rotr(w[i-15],18), shir(w[i-15],3))
    s1 = XORXOR_(rotr(w[i-2],17), rotr(w[i-2],19), shir(w[i-2],10))
    w[i] = add(add(add(w[i-16],s0), w[i-7]), s1)
        
#%%

# SHA-256 Algorithm

def sha256(message, inits=get_constants()):
    h0, h1, h2, h3, h4, h5, h6, h7 = initializer(inits[0])
    k = initializer(inits[1])
    chunks = preprocessMessage(message)
    for chunk in chunks:
        w = chunker(chunk, 32)
        for _ in range(48):
            w.append(32*[0])
        for i in range(16, 64):
            s0 = XORXOR_(rotr(w[i-15],7), rotr(w[i-15],18), shir(w[i-15],3))
            s1 = XORXOR_(rotr(w[i-2],17), rotr(w[i-2],19), shir(w[i-2],10))
            w[i] = add(add(add(w[i-16],s0), w[i-7]), s1)
        a=h0; b=h1; c=h2; d=h3; e=h4; f=h5; g=h6; h=h7;
        for j in range(64):
            S1 = XORXOR_(rotr(e,6), rotr(e,11), rotr(e,25))
            ch = XOR_(AND_(e,f), AND_(NOT_(e),g))
            temp1 = add(add(add(add(h,S1),ch), k[j]), w[j])
            S0 = XORXOR_(rotr(a,2), rotr(a,13), rotr(a,22))
            m = XORXOR_(AND_(a,b), AND_(a,c), AND_(b,c))
            temp2 = add(S0,m)
            h=g; g=f; f=e; e=add(d,temp1); d=c; c=b; b=a; a=add(temp1,temp2);
        h0=add(h0,a); h1=add(h1,b); h2=add(h2,c); h3=add(h3,d); h4=add(h4,e); h5=add(h5,f); h6=add(h6,g); h7=add(h7,h);
    digest = ''
    for val in [h0, h1, h2, h3, h4, h5, h6, h7]:
        digest += b2_to_b16(val)
    return digest