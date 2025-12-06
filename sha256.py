import struct

# 1. Constantes iniciales (Primeros 32 bits de la parte fraccionaria 
# de las raíces cuadradas de los primeros 8 números primos)
H_INICIAL = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
]

# 2. Constantes K (Primeros 32 bits de la parte fraccionaria 
# de las raíces cúbicas de los primeros 64 números primos)
K = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
]


def rotr(x, n):
    return ((x >> n) | (x << (32 - n))) & 0xFFFFFFFF

def shr(x, n):
    return (x >> n)

def ch(x, y, z):
    return (x & y) ^ (~x & z)

def maj(x, y, z):
    return (x & y) ^ (x & z) ^ (y & z)

def sigma0(x):
    return rotr(x, 2) ^ rotr(x, 13) ^ rotr(x, 22)

def sigma1(x):
    return rotr(x, 6) ^ rotr(x, 11) ^ rotr(x, 25)

def gamma0(x):
    return rotr(x, 7) ^ rotr(x, 18) ^ shr(x, 3)

def gamma1(x):
    return rotr(x, 17) ^ rotr(x, 19) ^ shr(x, 10)


def sha256_hash(mensaje: str) -> str:

    if isinstance(mensaje, str):
        mensaje = mensaje.encode('utf-8')
    
    length = len(mensaje) * 8 
    
    mensaje += b'\x80'
    
    while (len(mensaje) % 64) != 56:
        mensaje += b'\x00'
        
    mensaje += struct.pack('>Q', length)
    
    h = list(H_INICIAL)
    
    for i in range(0, len(mensaje), 64):
        chunk = mensaje[i:i+64]
        
        w = list(struct.unpack('>16I', chunk))
        
        for t in range(16, 64):
            s1 = gamma1(w[t-2])
            s0 = gamma0(w[t-15])
            res = (s1 + w[t-7] + s0 + w[t-16]) & 0xFFFFFFFF
            w.append(res)
            
        a, b, c, d, e, f, g, h_val = h
        
        for t in range(64):
            t1 = (h_val + sigma1(e) + ch(e, f, g) + K[t] + w[t]) & 0xFFFFFFFF
            t2 = (sigma0(a) + maj(a, b, c)) & 0xFFFFFFFF
            
            h_val = g
            g = f
            f = e
            e = (d + t1) & 0xFFFFFFFF
            d = c
            c = b
            b = a
            a = (t1 + t2) & 0xFFFFFFFF
            
        h[0] = (h[0] + a) & 0xFFFFFFFF
        h[1] = (h[1] + b) & 0xFFFFFFFF
        h[2] = (h[2] + c) & 0xFFFFFFFF
        h[3] = (h[3] + d) & 0xFFFFFFFF
        h[4] = (h[4] + e) & 0xFFFFFFFF
        h[5] = (h[5] + f) & 0xFFFFFFFF
        h[6] = (h[6] + g) & 0xFFFFFFFF
        h[7] = (h[7] + h_val) & 0xFFFFFFFF

    return ''.join(f'{x:08x}' for x in h)

if __name__ == "__main__":
    # Prueba rápida si se quiere ejecutar este archivo solo
    texto = "hola"
    print(f"Texto: {texto}")
    print(f"Hash : {sha256_hash(texto)}")