import sys

KEY = "plmoknijbuhvygctfxrdzeswaq"

def rc4(key, data):
    keylen = len(key)
    s = list(range(256))
    j = 0
    for i in range(256):
        j = (j + s[i] + ord(key[i % keylen])) % 256
        s[i], s[j] = s[j], s[i]

    i = j = 0
    encrypted = bytearray()
    for n in range(len(data)):
        i = (i + 1) % 256
        j = (j + s[i]) % 256
        s[i], s[j] = s[j], s[i]
        k = s[(s[i] + s[j]) % 256]
        encrypted.append(data[n] ^ k)

    return encrypted.decode("latin-1")

def print_cipher(ciphertext):
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

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python rc4.py <file>")
        sys.exit(1)

    with open(sys.argv[1], "rb") as f:
        data = f.read()

    encrypted_data = rc4(KEY, data)

    print_key(KEY)
    print_cipher(encrypted_data)