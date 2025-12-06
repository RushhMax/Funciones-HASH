RATE = 1088
CAPACITY = 512
STATE_SIZE = 1600
LANE_SIZE = 64

ROUNDS = 24

ROT = [
    [0, 36, 3, 41, 18],
    [1, 44, 10, 45, 2],
    [62, 6, 43, 15, 61],
    [28, 55, 25, 21, 56],
    [27, 20, 39, 8, 14]
]

RC = [
    0x0000000000000001, 0x0000000000008082,
    0x800000000000808A, 0x8000000080008000,
    0x000000000000808B, 0x0000000080000001,
    0x8000000080008081, 0x8000000000008009,
    0x000000000000008A, 0x0000000000000088,
    0x0000000080008009, 0x000000008000000A,
    0x000000008000808B, 0x800000000000008B,
    0x8000000000008089, 0x8000000000008003,
    0x8000000000008002, 0x8000000000000080,
    0x000000000000800A, 0x800000008000000A,
    0x8000000080008081, 0x8000000000008080,
    0x0000000080000001, 0x8000000080008008
]


def _rot(x, n):
    return ((x << n) | (x >> (64 - n))) & ((1 << 64) - 1)


def _keccak_f(state):
    for rnd in range(ROUNDS):
        C = [state[x][0] ^ state[x][1] ^ state[x][2] ^ state[x][3] ^ state[x][4] for x in range(5)]
        D = [C[(x - 1) % 5] ^ _rot(C[(x + 1) % 5], 1) for x in range(5)]

        # θ
        for x in range(5):
            for y in range(5):
                state[x][y] ^= D[x]

        # ρ & π
        B = [[0]*5 for _ in range(5)]
        for x in range(5):
            for y in range(5):
                B[y][(2*x + 3*y) % 5] = _rot(state[x][y], ROT[x][y])

        # χ
        for x in range(5):
            for y in range(5):
                state[x][y] = B[x][y] ^ ((~B[(x+1)%5][y]) & B[(x+2)%5][y])

        # ι
        state[0][0] ^= RC[rnd]

    return state


def sha3_256(texto: str) -> str:
    if not isinstance(texto, str):
        raise TypeError("La entrada debe ser texto (str).")
    if texto.strip() == "":
        raise ValueError("La entrada no puede estar vacía.")

    m = texto.encode("utf-8")

    padded = bytearray(m)
    padded.append(0x06)
    while (len(padded) * 8) % RATE != (RATE - 8):
        padded.append(0x00)
    padded.append(0x80)

    state = [[0]*5 for _ in range(5)]

    for i in range(0, len(padded), RATE//8):
        block = padded[i:i + RATE//8]

        j = 0
        for y in range(5):
            for x in range(5):
                if (x + 5*y) * 8 < RATE:
                    lane_bytes = block[j*8:(j+1)*8]
                    lane = int.from_bytes(lane_bytes, "little")
                    state[x][y] ^= lane
                    j += 1

        state = _keccak_f(state)

    output = b""
    while len(output) < 32:
        for y in range(5):
            for x in range(5):
                if len(output) < 32 and (x + 5*y) * 8 < RATE:
                    output += state[x][y].to_bytes(8, "little")
        if len(output) < 32:
            state = _keccak_f(state)

    return output[:32].hex()
