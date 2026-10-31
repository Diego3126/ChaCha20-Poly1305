"""Poly1305: código de autenticación de mensajes (RFC 8439, sección 2.5).

Produce una etiqueta (tag) de 16 bytes que demuestra que el mensaje no fue
modificado. Es aritmética de enteros grandes módulo el primo 2^130 - 5, y
Python maneja enteros de tamaño arbitrario, así que queda muy corto.
"""

PRIMO = (1 << 130) - 5
MASCARA_R = 0x0FFFFFFC0FFFFFFC0FFFFFFC0FFFFFFF  # "clamp" que exige la especificación


def poly1305(clave: bytes, mensaje: bytes) -> bytes:
    """Calcula la etiqueta Poly1305. `clave` son 32 bytes de un solo uso."""
    if len(clave) != 32:
        raise ValueError("La clave de Poly1305 debe tener 32 bytes")

    r = int.from_bytes(clave[:16], "little") & MASCARA_R
    s = int.from_bytes(clave[16:], "little")

    acumulador = 0
    for i in range(0, len(mensaje), 16):
        trozo = mensaje[i:i + 16]
        # Se agrega un byte 0x01 al final de cada trozo antes de leerlo como número.
        n = int.from_bytes(trozo + b"\x01", "little")
        acumulador = ((acumulador + n) * r) % PRIMO

    acumulador += s
    return (acumulador & ((1 << 128) - 1)).to_bytes(16, "little")
