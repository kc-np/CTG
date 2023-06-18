import codecs  # import codecs to convert hex to words
import random  # import random for elgamal
import whirlpool  # import whirlpool for whirlpool


#######################################################

# general functions

# Find gcd between two numbers
def gcd(a, b):
    if a < b:
        return gcd(b, a)
    elif a % b == 0:
        return b
    else:
        return gcd(b, a % b)


# Modular exponentiation
def power(a, b, c):
    return pow(a, b, c)


# split <string> into chunks of <chunk_size> characters
def splitString(message, chunk_size):
    return [message[i:i+chunk_size] for i in range(0, len(message), chunk_size)]


# idea functions

# Modular addition
def modAdd(a, b):
    return (a + b) % (2 ** 16)


# Modular multiplication
def modMultiply(a, b):
    return (a * b) % ((2 ** 16) + 1)


# Split plaintext into 4 blocks of 16 bits
def plainSplit(x):
    p1 = (x & (0xffff000000000000)) >> 48
    p2 = (x & (0x0000ffff00000000)) >> 32
    p3 = (x & (0x00000000ffff0000)) >> 16
    p4 = (x & (0x000000000000ffff))
    return p1, p2, p3, p4


# Generate subkeys for encryption
def keyGeneration(k):
    key = []
    key.append(k)
    for i in range(0, 6):
        key.append(
            ((key[i] * (2 ** 25)) & 0xffffffffffffffffffffffffffffffff) + (key[i] >> 103))
    subkeys = []
    for sk in key:
        subkeys.append((sk & (0xffff0000000000000000000000000000)) >> 112)
        subkeys.append((sk & (0x0000ffff000000000000000000000000)) >> 96)
        subkeys.append((sk & (0x00000000ffff00000000000000000000)) >> 80)
        subkeys.append((sk & (0x000000000000ffff0000000000000000)) >> 64)
        subkeys.append((sk & (0x0000000000000000ffff000000000000)) >> 48)
        subkeys.append((sk & (0x00000000000000000000ffff00000000)) >> 32)
        subkeys.append((sk & (0x000000000000000000000000ffff0000)) >> 16)
        subkeys.append((sk & (0x0000000000000000000000000000ffff)))
    subkeys = subkeys[:-4]
    return subkeys


# Inverse modular addition
def addInverse(k):
    n = 2 ** 16
    inv = n - k
    return inv


# Inverse modular multiplication
def multiplyInverse(a):
    m = (2 ** 16) + 1
    g = gcd(a, m)

    if (g != 1):
        print("Inverse doesn't exist")

    else:
        return power(a, -1, m)


# Generate subkeys for decryption
def invKeyGeneration(k):
    invk = []
    invk.extend(k)
    p = 0
    i = 48
    invk[i] = multiplyInverse(k[p])
    p = p + 1
    invk[i + 1] = addInverse(k[p])
    p = p + 1
    invk[i + 2] = addInverse(k[p])
    p = p + 1
    invk[i + 3] = multiplyInverse(k[p])
    p = p + 1

    for r in range(7, 0, -1):
        i = r * 6
        invk[i + 4] = k[p]
        p = p + 1
        invk[i + 5] = k[p]
        p = p + 1
        invk[i] = multiplyInverse(k[p])
        p = p + 1
        invk[i + 2] = addInverse(k[p])
        p = p + 1
        invk[i + 1] = addInverse(k[p])
        p = p + 1
        invk[i + 3] = multiplyInverse(k[p])
        p = p + 1

    invk[4] = k[p]
    p = p + 1
    invk[5] = k[p]
    p = p + 1
    invk[0] = multiplyInverse(k[p])
    p = p + 1
    invk[1] = addInverse(k[p])
    p = p + 1
    invk[2] = addInverse(k[p])
    p = p + 1
    invk[3] = multiplyInverse(k[p])
    return invk


# Operations for a round
def round(p, k1, k2, k3, k4, k5, k6):
    p1, p2, p3, p4 = plainSplit(p)
    s1 = modMultiply(p1, k1)
    s2 = modAdd(p2, k2)
    s3 = modAdd(p3, k3)
    s4 = modMultiply(p4, k4)
    s5 = s1 ^ s3
    s6 = s2 ^ s4
    s7 = modMultiply(s5, k5)
    s8 = modAdd(s6, s7)
    s9 = modMultiply(s8, k6)
    s10 = modAdd(s7, s9)
    r1 = s1 ^ s9
    r2 = s3 ^ s9
    r3 = s2 ^ s10
    r4 = s4 ^ s10
    r = (r1 << 48) + (r2 << 32) + (r3 << 16) + r4
    return r


# Operations for final round
def finalRound(p, k1, k2, k3, k4):
    p1, p3, p2, p4 = plainSplit(p)
    r1 = modMultiply(p1, k1)
    r2 = modAdd(p2, k2)
    r3 = modAdd(p3, k3)
    r4 = modMultiply(p4, k4)
    r = (r1 << 48) + (r2 << 32) + (r3 << 16) + r4
    return r


# Encryption
def iEncrypt(p, k):
    sk = keyGeneration(k)
    for i in range(0, 8):
        p = round(p, sk[i * 6], sk[i * 6 + 1], sk[i * 6 + 2],
                  sk[i * 6 + 3], sk[i * 6 + 4], sk[i * 6 + 5])
    p = finalRound(p, sk[48], sk[49], sk[50], sk[51])
    return p


# Decryption
def iDecrypt(c, k):
    sk = keyGeneration(k)
    sk = invKeyGeneration(sk)
    for i in range(0, 8):
        c = round(c, sk[i * 6], sk[i * 6 + 1], sk[i * 6 + 2],
                  sk[i * 6 + 3], sk[i * 6 + 4], sk[i * 6 + 5])
    c = finalRound(c, sk[48], sk[49], sk[50], sk[51])
    return c


#######################################################
# elgamal functions

# Generating large random numbers
def genKey(q):
    key = random.randint(pow(10, 20), q)
    while gcd(q, key) != 1:
        key = random.randint(pow(10, 20), q)

    return key


# Encryption
def egEncrypt(msg, q, h, g):
    enMsg = []

    k = genKey(q)  # Alice selects a number such that gcd(k, q) = 1
    s = power(h, k, q)
    p = power(g, k, q)

    for i in range(0, len(msg)):
        enMsg.append(msg[i])

    for i in range(0, len(enMsg)):
        enMsg[i] = s * ord(enMsg[i])

    return enMsg, p


# Decryption
def egDecrypt(en_msg, p, key, q):
    drMsg = []
    h = power(p, key, q)
    for i in range(0, len(en_msg)):
        drMsg.append(chr(int(en_msg[i] / h)))

    return drMsg


#######################################################
# whirlpool functions

# Hash message
def hashMsg(pt):
    newWP = whirlpool.new(pt.encode('utf-8'))
    md = newWP.hexdigest()

    return md


#######################################################
# combine all algorithms

msg = input("Enter message: ")

print()

#######################################################
# generate digital signature with elgamal and whirlpool

# hash msg
md = hashMsg(msg)  # md is the hashed msg
print("Hashed msg:", md)

# elgamal
# generate q1 and g1
q1 = random.randint(pow(10, 20), pow(10, 50))
g1 = random.randint(2, q1)

key1 = genKey(q1)  # private key
h1 = power(g1, key1, q1)  # public key
ds, p1 = egEncrypt(md, q1, h1, g1)  # ds is the encrypted md aka digital signature, p1 is the key for decryption
print("Encrypted md (digital signature):", ds)

print()

#######################################################
# encrypt message with idea

# get key
ideaKey = input("Enter key for IDEA: ")

while len(ideaKey) != 16:
    print("Key must be 16 characters.")
    ideaKey = input("Enter key for IDEA: ")

print()

# convert key into int to put into encrypt function
# convert key and plaintext into int to put into encrypt function
iKey = int(ideaKey.encode('utf-8').hex(), 16)

# split message into 64-bit (8-character) chunks
message_chunks = splitString(msg, 8)

ct1 = []  # ct1 is the list of idea encrypted blocks

# encrypt message with idea
for chunk in message_chunks:
    pt = int(chunk.encode('utf-8').hex(), 16)
    ct1.append(str(iEncrypt(pt, iKey)))

print("IDEA encrypted msg (ciphertext 1):", hex(int(''.join(ct1))))

print()

#######################################################
# encrypt idea key with elgamal

# generate q2 and g2
q2 = random.randint(pow(10, 20), pow(10, 50))
g2 = random.randint(2, q2)

key2 = genKey(q2)  # private key
h2 = power(g2, key2, q2)  # public key
ct2, p2 = egEncrypt(ideaKey, q2, h2, g2)  # ct2 is the encrypted idea key, p2 is the key for decryption
print("Encrypted IDEA key (ciphertext 2):", ct2)

print()

#######################################################
# both ct1 and ct2 are sent to the receiver
print("*** Message sent. ***")

print()

#######################################################
# decrypt elgamal to get idea key
dKey = egDecrypt(ct2, p2, key2, q2)
dKey = ''.join(dKey)
print("Decrypted IDEA key (ciphertext 2):", dKey)

print()

#######################################################
# convert decrypted idea key to correct type
iDKey = dKey.encode('utf-8').hex()
iDKey = int(iDKey, 16)

# decrypt message with idea
dmsg = []  #dmsg is the list of idea decrypted blocks

for block in ct1:
    decryptedBlock = iDecrypt(int(block), iDKey)

    # convert to words
    decryptedBytes = bytes(hex(decryptedBlock)[2:], encoding='utf-8')
    decoded = codecs.decode(decryptedBytes, 'hex')
    decryptedStr = str(decoded, 'utf-8')

    dmsg.append(decryptedStr)

print("Decrypted ciphertext 1:", ''.join(dmsg))

print()

#######################################################
# decrypt ds to get md1
md1 = egDecrypt(ds, p1, key1, q1)
md1 = ''.join(md1)
print("Decrypted hashed msg (md1):", md1)

print()

#######################################################
# hash message
md2 = hashMsg(''.join(dmsg))
print("Hashed msg (md2):", md2)

print()

#######################################################
# compare hash values
if md1 == md2:
    print("The two hash values match - message not altered")
else:
    print("The two hash values do not match - message altered")
