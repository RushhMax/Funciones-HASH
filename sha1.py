# sha1_manual.py
# Implementación MANUAL de SHA-1 sin hashlib

def _left_rotate(n, b):
    """Rotación circular a la izquierda de 32 bits."""
    return ((n << b) | (n >> (32 - b))) & 0xffffffff


def sha1_manual(mensaje: bytes) -> str:
    # Convertir a bytes UTF-8
    if isinstance(mensaje, bytes):
      raise TypeError("La función solo acepta texto (str), no bytes.")


    if mensaje.strip() == "":
        raise ValueError("La entrada no puede estar vacía.")

    mensaje = mensaje.encode("utf-8")

    # Longitud original en bits
    longitud_bits = len(mensaje) * 8

    # Padding: añadir bit '1'
    mensaje += b'\x80'

    # Añadir 0s hasta que el tamaño ≡ 448 (mod 512)
    while (len(mensaje) * 8) % 512 != 448:
        mensaje += b'\x00'

    # Añadir la longitud original (64 bits big-endian)
    mensaje += longitud_bits.to_bytes(8, byteorder='big')

    # Hash inicial (H0..H4)
    h0 = 0x67452301
    h1 = 0xEFCDAB89
    h2 = 0x98BADCFE
    h3 = 0x10325476
    h4 = 0xC3D2E1F0

    # Procesar bloques de 512 bits
    for i in range(0, len(mensaje), 64):
        bloque = mensaje[i:i+64]

        # Preparar palabras W
        w = [0] * 80

        # 16 palabras iniciales de 32 bits
        for j in range(16):
            w[j] = int.from_bytes(bloque[j*4:j*4+4], 'big')

        # Expandir a 80 palabras
        for j in range(16, 80):
            w[j] = _left_rotate(w[j-3] ^ w[j-8] ^ w[j-14] ^ w[j-16], 1)

        # Variables temporales
        a, b, c, d, e = h0, h1, h2, h3, h4

        # 80 rondas
        for t in range(80):
            if 0 <= t <= 19:
                f = (b & c) | ((~b) & d)
                k = 0x5A827999
            elif 20 <= t <= 39:
                f = b ^ c ^ d
                k = 0x6ED9EBA1
            elif 40 <= t <= 59:
                f = (b & c) | (b & d) | (c & d)
                k = 0x8F1BBCDC
            else:
                f = b ^ c ^ d
                k = 0xCA62C1D6

            temp = (_left_rotate(a, 5) + f + e + k + w[t]) & 0xffffffff
            e = d
            d = c
            c = _left_rotate(b, 30)
            b = a
            a = temp

        # Actualizar hash
        h0 = (h0 + a) & 0xffffffff
        h1 = (h1 + b) & 0xffffffff
        h2 = (h2 + c) & 0xffffffff
        h3 = (h3 + d) & 0xffffffff
        h4 = (h4 + e) & 0xffffffff

    # Concatenar resultado final
    return ''.join(format(x, '08x') for x in [h0, h1, h2, h3, h4])



# Para pruebas rápidas desde consola
if __name__ == "__main__":
    print("=== Calculadora SHA-1 ===")

    while True:
        texto = input("Ingrese texto para calcular SHA-1: ")

        validar_entrada(texto)
        try:
            resultado = sha1_manual(texto)
            print(f"SHA-1: {resultado}\n")
        except ValueError as e:
            print(f"Error: {e}\n")