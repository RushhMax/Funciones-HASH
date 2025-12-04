import struct


class MD4:
    """Clase para calcular el hash MD4 de un mensaje"""

    def __init__(self):
        # Valores iniciales de los registros (en little-endian)
        self.A = 0x67452301
        self.B = 0xEFCDAB89
        self.C = 0x98BADCFE
        self.D = 0x10325476

    def _f(self, x, y, z):
        """Función auxiliar F"""
        return ((x & y) | ((~x & 0xFFFFFFFF) & z)) & 0xFFFFFFFF

    def _g(self, x, y, z):
        """Función auxiliar G"""
        return ((x & y) | (x & z) | (y & z)) & 0xFFFFFFFF

    def _h(self, x, y, z):
        """Función auxiliar H"""
        return (x ^ y ^ z) & 0xFFFFFFFF

    def _left_rotate(self, n, b):
        """Rotación a la izquierda de n por b bits"""
        return ((n << b) | (n >> (32 - b))) & 0xFFFFFFFF

    def _pad_message(self, message):
        """Rellena el mensaje según el estándar MD4"""
        msg_len = len(message)
        message += b'\x80'

        # Añadir ceros hasta que el mensaje sea congruente a 448 mod 512
        while len(message) % 64 != 56:
            message += b'\x00'

        # Añadir la longitud original del mensaje en bits (64 bits, little-endian)
        message += struct.pack('<Q', msg_len * 8)

        return message

    def _process_block(self, block):
        """Procesa un bloque de 512 bits (64 bytes)"""
        # Dividir el bloque en 16 palabras de 32 bits (little-endian)
        X = list(struct.unpack('<16I', block))

        # Guardar los valores iniciales
        AA, BB, CC, DD = self.A, self.B, self.C, self.D

        # Ronda 1
        indices_round1 = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]
        shifts_round1 = [3, 7, 11, 19, 3, 7, 11, 19, 3, 7, 11, 19, 3, 7, 11, 19]

        for i in range(16):
            k = indices_round1[i]
            s = shifts_round1[i]
            self.A = self._left_rotate((self.A + self._f(self.B, self.C, self.D) + X[k]) & 0xFFFFFFFF, s)
            self.A, self.B, self.C, self.D = self.D, self.A, self.B, self.C

        # Ronda 2
        indices_round2 = [0, 4, 8, 12, 1, 5, 9, 13, 2, 6, 10, 14, 3, 7, 11, 15]
        shifts_round2 = [3, 5, 9, 13, 3, 5, 9, 13, 3, 5, 9, 13, 3, 5, 9, 13]

        for i in range(16):
            k = indices_round2[i]
            s = shifts_round2[i]
            self.A = self._left_rotate((self.A + self._g(self.B, self.C, self.D) + X[k] + 0x5A827999) & 0xFFFFFFFF, s)
            self.A, self.B, self.C, self.D = self.D, self.A, self.B, self.C

        # Ronda 3
        indices_round3 = [0, 8, 4, 12, 2, 10, 6, 14, 1, 9, 5, 13, 3, 11, 7, 15]
        shifts_round3 = [3, 9, 11, 15, 3, 9, 11, 15, 3, 9, 11, 15, 3, 9, 11, 15]

        for i in range(16):
            k = indices_round3[i]
            s = shifts_round3[i]
            self.A = self._left_rotate((self.A + self._h(self.B, self.C, self.D) + X[k] + 0x6ED9EBA1) & 0xFFFFFFFF, s)
            self.A, self.B, self.C, self.D = self.D, self.A, self.B, self.C

        # Sumar los valores originales
        self.A = (self.A + AA) & 0xFFFFFFFF
        self.B = (self.B + BB) & 0xFFFFFFFF
        self.C = (self.C + CC) & 0xFFFFFFFF
        self.D = (self.D + DD) & 0xFFFFFFFF

    def hash(self, message):
        """
        Calcula el hash MD4 de un mensaje

        Args:
            message: Mensaje en bytes o string

        Returns:
            Hash MD4 en formato hexadecimal
        """
        # Convertir a bytes si es necesario
        if isinstance(message, str):
            message = message.encode('utf-8')

        # Reiniciar los valores
        self.A = 0x67452301
        self.B = 0xEFCDAB89
        self.C = 0x98BADCFE
        self.D = 0x10325476

        # Rellenar el mensaje
        padded_message = self._pad_message(message)

        # Procesar cada bloque de 512 bits
        for i in range(0, len(padded_message), 64):
            block = padded_message[i:i+64]
            self._process_block(block)

        # Retornar el resultado en formato hexadecimal (little-endian)
        result = struct.pack('<4I', self.A, self.B, self.C, self.D)
        return result.hex()


def md4_hash(message):
    """
    Función de conveniencia para calcular el hash MD4

    Args:
        message: Mensaje en bytes o string

    Returns:
        Hash MD4 en formato hexadecimal
    """
    md4 = MD4()
    return md4.hash(message)
