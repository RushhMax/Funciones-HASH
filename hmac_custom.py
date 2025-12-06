import hashlib

def hmac_custom(clave: str, mensaje: str, algoritmo: str = "sha256") -> str:
    if clave.strip() == "" or mensaje.strip() == "":
        raise ValueError("Clave y mensaje no pueden estar vacíos.")

    clave = clave.encode()
    mensaje = mensaje.encode()

    block_size = 64  # 512 bits

    if len(clave) > block_size:
        clave = hashlib.sha256(clave).digest()
    if len(clave) < block_size:
        clave = clave + b"\x00" * (block_size - len(clave))

    opad = bytes((b ^ 0x5C) for b in clave)
    ipad = bytes((b ^ 0x36) for b in clave)

    if algoritmo.lower() == "md5":
        inner = hashlib.md5(ipad + mensaje).digest()
        return hashlib.md5(opad + inner).hexdigest()

    elif algoritmo.lower() == "sha256":
        inner = hashlib.sha256(ipad + mensaje).digest()
        return hashlib.sha256(opad + inner).hexdigest()

    else:
        raise ValueError("Algoritmo no soportado en HMAC")
