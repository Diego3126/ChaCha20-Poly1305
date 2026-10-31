"""ChaCha20: cifrado de flujo (RFC 8439, sección 2).

Idea central: a partir de una clave, un nonce y un contador se genera un
"keystream" pseudoaleatorio de 64 bytes por bloque. Cifrar es hacer XOR entre
el mensaje y ese keystream; descifrar es exactamente la misma operación.

Solo se usan tres operaciones sobre enteros de 32 bits (por eso se llama ARX):
    A = Add (suma módulo 2^32)
    R = Rotate (rotación de bits a la izquierda)
    X = XOR
"""

import struct

MASCARA_32 = 0xFFFFFFFF

# Las 4 palabras iniciales son la cadena ASCII "expand 32-byte k" en little-endian.
CONSTANTES = (0x61707865, 0x3320646E, 0x79622D32, 0x6B206574)

TAMANO_CLAVE = 32   # 256 bits
TAMANO_NONCE = 12   # 96 bits
TAMANO_BLOQUE = 64  # 512 bits


def rotar_izquierda(valor: int, bits: int) -> int:
    """Rota un entero de 32 bits `bits` posiciones a la izquierda."""
    return ((valor << bits) & MASCARA_32) | (valor >> (32 - bits))


def cuarto_de_ronda(e: list, a: int, b: int, c: int, d: int) -> None:
    """Quarter round: mezcla cuatro palabras del estado (modifica `e` en sitio)."""
    e[a] = (e[a] + e[b]) & MASCARA_32
    e[d] = rotar_izquierda(e[d] ^ e[a], 16)

    e[c] = (e[c] + e[d]) & MASCARA_32
    e[b] = rotar_izquierda(e[b] ^ e[c], 12)

    e[a] = (e[a] + e[b]) & MASCARA_32
    e[d] = rotar_izquierda(e[d] ^ e[a], 8)

    e[c] = (e[c] + e[d]) & MASCARA_32
    e[b] = rotar_izquierda(e[b] ^ e[c], 7)


def estado_inicial(clave: bytes, contador: int, nonce: bytes) -> list:
    """Construye la matriz de estado de 4x4 palabras de 32 bits.

        constante constante constante constante
        clave     clave     clave     clave
        clave     clave     clave     clave
        contador  nonce     nonce     nonce
    """
    if len(clave) != TAMANO_CLAVE:
        raise ValueError("La clave debe tener 32 bytes")
    if len(nonce) != TAMANO_NONCE:
        raise ValueError("El nonce debe tener 12 bytes")
    if not 0 <= contador <= MASCARA_32:
        raise ValueError("El contador debe caber en 32 bits")

    return (
        list(CONSTANTES)
        + list(struct.unpack("<8I", clave))
        + [contador]
        + list(struct.unpack("<3I", nonce))
    )


def aplicar_rondas(estado: list) -> list:
    """20 rondas = 10 iteraciones de (4 rondas por columnas + 4 por diagonales)."""
    e = list(estado)
    for _ in range(10):
        # Rondas de columna
        cuarto_de_ronda(e, 0, 4, 8, 12)
        cuarto_de_ronda(e, 1, 5, 9, 13)
        cuarto_de_ronda(e, 2, 6, 10, 14)
        cuarto_de_ronda(e, 3, 7, 11, 15)
        # Rondas diagonales
        cuarto_de_ronda(e, 0, 5, 10, 15)
        cuarto_de_ronda(e, 1, 6, 11, 12)
        cuarto_de_ronda(e, 2, 7, 8, 13)
        cuarto_de_ronda(e, 3, 4, 9, 14)
    return e


def bloque(clave: bytes, contador: int, nonce: bytes) -> bytes:
    """Genera 64 bytes de keystream para un contador dado."""
    inicial = estado_inicial(clave, contador, nonce)
    mezclado = aplicar_rondas(inicial)
    # Se suma el estado inicial al final: sin este paso el proceso sería reversible.
    final = [(m + i) & MASCARA_32 for m, i in zip(mezclado, inicial)]
    return struct.pack("<16I", *final)


def cifrar(clave: bytes, contador: int, nonce: bytes, datos: bytes) -> bytes:
    """Cifra (o descifra) `datos` haciendo XOR con el keystream."""
    salida = bytearray()
    for i in range(0, len(datos), TAMANO_BLOQUE):
        keystream = bloque(clave, contador + i // TAMANO_BLOQUE, nonce)
        trozo = datos[i:i + TAMANO_BLOQUE]
        salida.extend(a ^ b for a, b in zip(trozo, keystream))
    return bytes(salida)
