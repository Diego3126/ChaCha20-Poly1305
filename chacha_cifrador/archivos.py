"""Cifrado de archivos con contraseña usando ChaCha20-Poly1305.

Formato del archivo cifrado (.chacha):

    +--------+-----------+-----------+----------------+-----------+
    | "CHA1" | salt (16) | nonce(12) | texto cifrado  | tag (16)  |
    +--------+-----------+-----------+----------------+-----------+
      \\___________ cabecera (autenticada) ___________/

La cabecera se pasa como "datos asociados" (AAD): no va cifrada, pero si alguien
la modifica, el tag deja de coincidir y el descifrado falla.
"""

import hashlib
import os

from . import aead

MAGIA = b"CHA1"
TAMANO_SALT = 16
TAMANO_NONCE = 12
TAMANO_CABECERA = len(MAGIA) + TAMANO_SALT + TAMANO_NONCE

# Parámetros de scrypt (derivación de clave a partir de la contraseña).
SCRYPT_N = 2 ** 15
SCRYPT_R = 8
SCRYPT_P = 1


class FormatoInvalido(Exception):
    """El archivo no tiene el formato esperado."""


def derivar_clave(contrasena: str, salt: bytes) -> bytes:
    """Convierte una contraseña en una clave de 32 bytes (lenta a propósito)."""
    return hashlib.scrypt(
        contrasena.encode("utf-8"),
        salt=salt,
        n=SCRYPT_N,
        r=SCRYPT_R,
        p=SCRYPT_P,
        maxmem=128 * 1024 * 1024,
        dklen=32,
    )


def cifrar_bytes(datos: bytes, contrasena: str) -> bytes:
    salt = os.urandom(TAMANO_SALT)
    nonce = os.urandom(TAMANO_NONCE)  # nunca se debe repetir con la misma clave
    clave = derivar_clave(contrasena, salt)
    cabecera = MAGIA + salt + nonce
    texto_cifrado, tag = aead.cifrar(clave, nonce, datos, aad=cabecera)
    return cabecera + texto_cifrado + tag


def descifrar_bytes(contenido: bytes, contrasena: str) -> bytes:
    if len(contenido) < TAMANO_CABECERA + aead.TAMANO_TAG or not contenido.startswith(MAGIA):
        raise FormatoInvalido("El archivo no parece haber sido cifrado con esta herramienta")
    cabecera = contenido[:TAMANO_CABECERA]
    salt = cabecera[len(MAGIA):len(MAGIA) + TAMANO_SALT]
    nonce = cabecera[len(MAGIA) + TAMANO_SALT:]
    texto_cifrado = contenido[TAMANO_CABECERA:-aead.TAMANO_TAG]
    tag = contenido[-aead.TAMANO_TAG:]
    clave = derivar_clave(contrasena, salt)
    return aead.descifrar(clave, nonce, texto_cifrado, tag, aad=cabecera)


def cifrar_archivo(origen: str, destino: str, contrasena: str) -> None:
    with open(origen, "rb") as f:
        datos = f.read()
    with open(destino, "wb") as f:
        f.write(cifrar_bytes(datos, contrasena))


def descifrar_archivo(origen: str, destino: str, contrasena: str) -> None:
    with open(origen, "rb") as f:
        contenido = f.read()
    datos = descifrar_bytes(contenido, contrasena)  # si falla, no se crea el destino
    with open(destino, "wb") as f:
        f.write(datos)
