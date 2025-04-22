import struct

# Константи K: перші 32 біти дробової частини кубічних коренів перших 64 простих чисел
K = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
    0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
    0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
    0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
    0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
    0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
]

# Початкові H: перші 32 біти дробової частини квадратних коренів перших 8 простих
H0_INIT = [
    0x6a09e667, 0xbb67ae85,
    0x3c6ef372, 0xa54ff53a,
    0x510e527f, 0x9b05688c,
    0x1f83d9ab, 0x5be0cd19,
]

def _rightrotate(x: int, n: int) -> int:
    return ((x >> n) | (x << (32 - n))) & 0xFFFFFFFF

def sha256(data: bytes) -> bytes:
    # 1) Pre-processing: padding
    length = len(data) * 8
    data += b'\x80'
    # pad with zeros until length ≡ 448 mod 512
    while (len(data) * 8) % 512 != 448:
        data += b'\x00'
    # append original length as 64-bit big-endian
    data += struct.pack('>Q', length)

    # 2) Initialize hash values
    H = H0_INIT.copy()

    # 3) Process the message in successive 512-bit chunks
    for chunk_start in range(0, len(data), 64):
        chunk = data[chunk_start:chunk_start + 64]
        # create message schedule W[0..63]
        W = list(struct.unpack('>16L', chunk))
        for i in range(16, 64):
            s0 = (_rightrotate(W[i-15], 7) ^
                  _rightrotate(W[i-15], 18) ^
                  (W[i-15] >> 3))
            s1 = (_rightrotate(W[i-2], 17) ^
                  _rightrotate(W[i-2], 19) ^
                  (W[i-2] >> 10))
            W.append((W[i-16] + s0 + W[i-7] + s1) & 0xFFFFFFFF)

        # Initialize working variables a–h
        a, b, c, d, e, f, g, h = H

        # Compression function main loop
        for i in range(64):
            S1 = (_rightrotate(e, 6) ^
                  _rightrotate(e, 11) ^
                  _rightrotate(e, 25))
            ch = (e & f) ^ (~e & g)
            temp1 = (h + S1 + ch + K[i] + W[i]) & 0xFFFFFFFF
            S0 = (_rightrotate(a, 2) ^
                  _rightrotate(a, 13) ^
                  _rightrotate(a, 22))
            maj = (a & b) ^ (a & c) ^ (b & c)
            temp2 = (S0 + maj) & 0xFFFFFFFF

            h = g
            g = f
            f = e
            e = (d + temp1) & 0xFFFFFFFF
            d = c
            c = b
            b = a
            a = (temp1 + temp2) & 0xFFFFFFFF

        # Add the compressed chunk to the current hash value
        H = [
            (H[0] + a) & 0xFFFFFFFF,
            (H[1] + b) & 0xFFFFFFFF,
            (H[2] + c) & 0xFFFFFFFF,
            (H[3] + d) & 0xFFFFFFFF,
            (H[4] + e) & 0xFFFFFFFF,
            (H[5] + f) & 0xFFFFFFFF,
            (H[6] + g) & 0xFFFFFFFF,
            (H[7] + h) & 0xFFFFFFFF,
        ]

    # Produce the final hash value (big-endian)
    return b"".join(struct.pack('>I', hval) for hval in H)

def sha256_hex(data: bytes) -> str:
    return sha256(data).hex()

def verify(data: bytes, expected_hex_hash: str) -> bool:
    """
    Перевіряє, чи дає дані `data` той самий хеш, що `expected_hex_hash`.
    Повертає True (коректний), якщо збігається, інакше False.
    """
    return sha256_hex(data) == expected_hex_hash

if __name__ == "__main__":
    samples = [b"", b"a", b"abc", b"hello world"]
    for s in samples:
        print(f"'{s.decode()}' → {sha256_hex(s)}")

    # Простi перевiрки
    assert sha256_hex(b"test") == sha256_hex(b"test")
    assert sha256_hex(b"foo") != sha256_hex(b"bar")
    print("\nSHA‑256 works correctly.")
    
     # Уявімо, що це "пароль", який ми зберегли в базі як SHA-256
    correct_secret = b"TopSecret123"
    stored_hash = sha256_hex(correct_secret)
    print("Saved hash:", stored_hash)

    # Сценарій 1: користувач вводить правильний пароль
    attempt1 = b"TopSecret123"
    ok1 = verify(attempt1, stored_hash)
    print(f"Try {attempt1!r}: ", "Right" if ok1 else "Wrong")

    # Сценарій 2: користувач вводить неправильний пароль
    attempt2 = b"WrongPassword"
    ok2 = verify(attempt2, stored_hash)
    print(f"Try {attempt2!r}: ", "Right" if ok2 else "Wrong")

