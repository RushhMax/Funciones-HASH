import struct
import math


class MD5:
    """Clase para calcular el hash MD5 de un mensaje"""

    def __init__(self):
        # Valores iniciales de los registros (en little-endian)
        self.A = 0x67452301
        self.B = 0xEFCDAB89
        self.C = 0x98BADCFE
        self.D = 0x10325476

        # Tabla de constantes (seno)
        self.T = [int(abs(math.sin(i + 1)) * 2**32) & 0xFFFFFFFF for i in range(64)]

    def _f(self, x, y, z):
        """Función auxiliar F"""
        return ((x & y) | ((~x & 0xFFFFFFFF) & z)) & 0xFFFFFFFF

    def _g(self, x, y, z):
        """Función auxiliar G"""
        return ((x & z) | (y & (~z & 0xFFFFFFFF))) & 0xFFFFFFFF

    def _h(self, x, y, z):
        """Función auxiliar H"""
        return (x ^ y ^ z) & 0xFFFFFFFF

    def _i(self, x, y, z):
        """Función auxiliar I"""
        return (y ^ (x | (~z & 0xFFFFFFFF))) & 0xFFFFFFFF

    def _left_rotate(self, n, b):
        """Rotación a la izquierda de n por b bits"""
        return ((n << b) | (n >> (32 - b))) & 0xFFFFFFFF

    def _pad_message(self, message):
        """Rellena el mensaje según el estándar MD5"""
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

        # Copiar los valores actuales a variables locales
        a, b, c, d = self.A, self.B, self.C, self.D

        # Ronda 1 - Utilizando la función F
        # FF(a, b, c, d, x, s, ac)
        a = (b + self._left_rotate((a + self._f(b, c, d) + X[0] + self.T[0]) & 0xFFFFFFFF, 7)) & 0xFFFFFFFF
        d = (a + self._left_rotate((d + self._f(a, b, c) + X[1] + self.T[1]) & 0xFFFFFFFF, 12)) & 0xFFFFFFFF
        c = (d + self._left_rotate((c + self._f(d, a, b) + X[2] + self.T[2]) & 0xFFFFFFFF, 17)) & 0xFFFFFFFF
        b = (c + self._left_rotate((b + self._f(c, d, a) + X[3] + self.T[3]) & 0xFFFFFFFF, 22)) & 0xFFFFFFFF

        a = (b + self._left_rotate((a + self._f(b, c, d) + X[4] + self.T[4]) & 0xFFFFFFFF, 7)) & 0xFFFFFFFF
        d = (a + self._left_rotate((d + self._f(a, b, c) + X[5] + self.T[5]) & 0xFFFFFFFF, 12)) & 0xFFFFFFFF
        c = (d + self._left_rotate((c + self._f(d, a, b) + X[6] + self.T[6]) & 0xFFFFFFFF, 17)) & 0xFFFFFFFF
        b = (c + self._left_rotate((b + self._f(c, d, a) + X[7] + self.T[7]) & 0xFFFFFFFF, 22)) & 0xFFFFFFFF

        a = (b + self._left_rotate((a + self._f(b, c, d) + X[8] + self.T[8]) & 0xFFFFFFFF, 7)) & 0xFFFFFFFF
        d = (a + self._left_rotate((d + self._f(a, b, c) + X[9] + self.T[9]) & 0xFFFFFFFF, 12)) & 0xFFFFFFFF
        c = (d + self._left_rotate((c + self._f(d, a, b) + X[10] + self.T[10]) & 0xFFFFFFFF, 17)) & 0xFFFFFFFF
        b = (c + self._left_rotate((b + self._f(c, d, a) + X[11] + self.T[11]) & 0xFFFFFFFF, 22)) & 0xFFFFFFFF

        a = (b + self._left_rotate((a + self._f(b, c, d) + X[12] + self.T[12]) & 0xFFFFFFFF, 7)) & 0xFFFFFFFF
        d = (a + self._left_rotate((d + self._f(a, b, c) + X[13] + self.T[13]) & 0xFFFFFFFF, 12)) & 0xFFFFFFFF
        c = (d + self._left_rotate((c + self._f(d, a, b) + X[14] + self.T[14]) & 0xFFFFFFFF, 17)) & 0xFFFFFFFF
        b = (c + self._left_rotate((b + self._f(c, d, a) + X[15] + self.T[15]) & 0xFFFFFFFF, 22)) & 0xFFFFFFFF

        # Ronda 2 - Utilizando la función G
        a = (b + self._left_rotate((a + self._g(b, c, d) + X[1] + self.T[16]) & 0xFFFFFFFF, 5)) & 0xFFFFFFFF
        d = (a + self._left_rotate((d + self._g(a, b, c) + X[6] + self.T[17]) & 0xFFFFFFFF, 9)) & 0xFFFFFFFF
        c = (d + self._left_rotate((c + self._g(d, a, b) + X[11] + self.T[18]) & 0xFFFFFFFF, 14)) & 0xFFFFFFFF
        b = (c + self._left_rotate((b + self._g(c, d, a) + X[0] + self.T[19]) & 0xFFFFFFFF, 20)) & 0xFFFFFFFF

        a = (b + self._left_rotate((a + self._g(b, c, d) + X[5] + self.T[20]) & 0xFFFFFFFF, 5)) & 0xFFFFFFFF
        d = (a + self._left_rotate((d + self._g(a, b, c) + X[10] + self.T[21]) & 0xFFFFFFFF, 9)) & 0xFFFFFFFF
        c = (d + self._left_rotate((c + self._g(d, a, b) + X[15] + self.T[22]) & 0xFFFFFFFF, 14)) & 0xFFFFFFFF
        b = (c + self._left_rotate((b + self._g(c, d, a) + X[4] + self.T[23]) & 0xFFFFFFFF, 20)) & 0xFFFFFFFF

        a = (b + self._left_rotate((a + self._g(b, c, d) + X[9] + self.T[24]) & 0xFFFFFFFF, 5)) & 0xFFFFFFFF
        d = (a + self._left_rotate((d + self._g(a, b, c) + X[14] + self.T[25]) & 0xFFFFFFFF, 9)) & 0xFFFFFFFF
        c = (d + self._left_rotate((c + self._g(d, a, b) + X[3] + self.T[26]) & 0xFFFFFFFF, 14)) & 0xFFFFFFFF
        b = (c + self._left_rotate((b + self._g(c, d, a) + X[8] + self.T[27]) & 0xFFFFFFFF, 20)) & 0xFFFFFFFF

        a = (b + self._left_rotate((a + self._g(b, c, d) + X[13] + self.T[28]) & 0xFFFFFFFF, 5)) & 0xFFFFFFFF
        d = (a + self._left_rotate((d + self._g(a, b, c) + X[2] + self.T[29]) & 0xFFFFFFFF, 9)) & 0xFFFFFFFF
        c = (d + self._left_rotate((c + self._g(d, a, b) + X[7] + self.T[30]) & 0xFFFFFFFF, 14)) & 0xFFFFFFFF
        b = (c + self._left_rotate((b + self._g(c, d, a) + X[12] + self.T[31]) & 0xFFFFFFFF, 20)) & 0xFFFFFFFF

        # Ronda 3 - Utilizando la función H
        a = (b + self._left_rotate((a + self._h(b, c, d) + X[5] + self.T[32]) & 0xFFFFFFFF, 4)) & 0xFFFFFFFF
        d = (a + self._left_rotate((d + self._h(a, b, c) + X[8] + self.T[33]) & 0xFFFFFFFF, 11)) & 0xFFFFFFFF
        c = (d + self._left_rotate((c + self._h(d, a, b) + X[11] + self.T[34]) & 0xFFFFFFFF, 16)) & 0xFFFFFFFF
        b = (c + self._left_rotate((b + self._h(c, d, a) + X[14] + self.T[35]) & 0xFFFFFFFF, 23)) & 0xFFFFFFFF

        a = (b + self._left_rotate((a + self._h(b, c, d) + X[1] + self.T[36]) & 0xFFFFFFFF, 4)) & 0xFFFFFFFF
        d = (a + self._left_rotate((d + self._h(a, b, c) + X[4] + self.T[37]) & 0xFFFFFFFF, 11)) & 0xFFFFFFFF
        c = (d + self._left_rotate((c + self._h(d, a, b) + X[7] + self.T[38]) & 0xFFFFFFFF, 16)) & 0xFFFFFFFF
        b = (c + self._left_rotate((b + self._h(c, d, a) + X[10] + self.T[39]) & 0xFFFFFFFF, 23)) & 0xFFFFFFFF

        a = (b + self._left_rotate((a + self._h(b, c, d) + X[13] + self.T[40]) & 0xFFFFFFFF, 4)) & 0xFFFFFFFF
        d = (a + self._left_rotate((d + self._h(a, b, c) + X[0] + self.T[41]) & 0xFFFFFFFF, 11)) & 0xFFFFFFFF
        c = (d + self._left_rotate((c + self._h(d, a, b) + X[3] + self.T[42]) & 0xFFFFFFFF, 16)) & 0xFFFFFFFF
        b = (c + self._left_rotate((b + self._h(c, d, a) + X[6] + self.T[43]) & 0xFFFFFFFF, 23)) & 0xFFFFFFFF

        a = (b + self._left_rotate((a + self._h(b, c, d) + X[9] + self.T[44]) & 0xFFFFFFFF, 4)) & 0xFFFFFFFF
        d = (a + self._left_rotate((d + self._h(a, b, c) + X[12] + self.T[45]) & 0xFFFFFFFF, 11)) & 0xFFFFFFFF
        c = (d + self._left_rotate((c + self._h(d, a, b) + X[15] + self.T[46]) & 0xFFFFFFFF, 16)) & 0xFFFFFFFF
        b = (c + self._left_rotate((b + self._h(c, d, a) + X[2] + self.T[47]) & 0xFFFFFFFF, 23)) & 0xFFFFFFFF

        # Ronda 4 - Utilizando la función I
        a = (b + self._left_rotate((a + self._i(b, c, d) + X[0] + self.T[48]) & 0xFFFFFFFF, 6)) & 0xFFFFFFFF
        d = (a + self._left_rotate((d + self._i(a, b, c) + X[7] + self.T[49]) & 0xFFFFFFFF, 10)) & 0xFFFFFFFF
        c = (d + self._left_rotate((c + self._i(d, a, b) + X[14] + self.T[50]) & 0xFFFFFFFF, 15)) & 0xFFFFFFFF
        b = (c + self._left_rotate((b + self._i(c, d, a) + X[5] + self.T[51]) & 0xFFFFFFFF, 21)) & 0xFFFFFFFF

        a = (b + self._left_rotate((a + self._i(b, c, d) + X[12] + self.T[52]) & 0xFFFFFFFF, 6)) & 0xFFFFFFFF
        d = (a + self._left_rotate((d + self._i(a, b, c) + X[3] + self.T[53]) & 0xFFFFFFFF, 10)) & 0xFFFFFFFF
        c = (d + self._left_rotate((c + self._i(d, a, b) + X[10] + self.T[54]) & 0xFFFFFFFF, 15)) & 0xFFFFFFFF
        b = (c + self._left_rotate((b + self._i(c, d, a) + X[1] + self.T[55]) & 0xFFFFFFFF, 21)) & 0xFFFFFFFF

        a = (b + self._left_rotate((a + self._i(b, c, d) + X[8] + self.T[56]) & 0xFFFFFFFF, 6)) & 0xFFFFFFFF
        d = (a + self._left_rotate((d + self._i(a, b, c) + X[15] + self.T[57]) & 0xFFFFFFFF, 10)) & 0xFFFFFFFF
        c = (d + self._left_rotate((c + self._i(d, a, b) + X[6] + self.T[58]) & 0xFFFFFFFF, 15)) & 0xFFFFFFFF
        b = (c + self._left_rotate((b + self._i(c, d, a) + X[13] + self.T[59]) & 0xFFFFFFFF, 21)) & 0xFFFFFFFF

        a = (b + self._left_rotate((a + self._i(b, c, d) + X[4] + self.T[60]) & 0xFFFFFFFF, 6)) & 0xFFFFFFFF
        d = (a + self._left_rotate((d + self._i(a, b, c) + X[11] + self.T[61]) & 0xFFFFFFFF, 10)) & 0xFFFFFFFF
        c = (d + self._left_rotate((c + self._i(d, a, b) + X[2] + self.T[62]) & 0xFFFFFFFF, 15)) & 0xFFFFFFFF
        b = (c + self._left_rotate((b + self._i(c, d, a) + X[9] + self.T[63]) & 0xFFFFFFFF, 21)) & 0xFFFFFFFF

        # Sumar los valores originales
        self.A = (self.A + a) & 0xFFFFFFFF
        self.B = (self.B + b) & 0xFFFFFFFF
        self.C = (self.C + c) & 0xFFFFFFFF
        self.D = (self.D + d) & 0xFFFFFFFF

    def hash(self, message):
        """
        Calcula el hash MD5 de un mensaje

        Args:
            message: Mensaje en bytes o string

        Returns:
            Hash MD5 en formato hexadecimal
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


def md5_hash(message):
    """
    Función de conveniencia para calcular el hash MD5

    Args:
        message: Mensaje en bytes o string

    Returns:
        Hash MD5 en formato hexadecimal
    """
    md5 = MD5()
    return md5.hash(message)
