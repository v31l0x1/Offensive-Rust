import base64
import sys

KEY = "plmoknijbuhvygctfxrdzeswaq"

def xor(data, key):
    key = str(key)
    l = len(key)
    output = bytearray()

    for i in range(len(data)):
        current = data[i]
        current_key = key[i % len(key)]
        output.append(current ^ ord(current_key))

    return output.decode("latin1")

def printCiphertext(ciphertext):
    print(
        "const SHELLCODE: &[u8] = &[ 0x"
        + ", 0x".join(hex(ord(x))[2:] for x in ciphertext)
        + " ];"
    )

def print_key(key):
    print(
        "const KEY: &[u8] = &[ 0x"
        + ", 0x".join(hex(ord(x))[2:] for x in key)
        + " ];"
    )

try:
    plaintext = open(sys.argv[1], "rb").read()
except:
    print("File argument needed! %s <raw payload file>" % sys.argv[0])
    sys.exit()

ciphertext = xor(plaintext, KEY)
printCiphertext(ciphertext)
print_key(KEY)