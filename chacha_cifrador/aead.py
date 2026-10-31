"""ChaCha20-Poly1305 AEAD (RFC 8439, sección 2.8).

AEAD = cifrado autenticado con datos asociados. Además de ocultar el mensaje,
garantiza que nadie lo modificó (ni a él ni a los datos asociados).
"""

import hmac
import struct

from . import chacha20
from .poly1305 import poly1305

TAMANO_TAG = 16


class EtiquetaInvalida(Exception):
    """El tag no coincide: contraseña incorrecta o datos alterados."""


def _relleno(datos: bytes) -> bytes:
    """Ceros necesarios para llegar a un múltiplo de 16 bytes."""
    return b"\x00" * (-len(datos) % 16)


def _clave_poly1305(clave: bytes, nonce: bytes) -> bytes:
    """La clave de un solo uso de Poly1305 sale del bloque 0 de ChaCha20."""
    return chacha20.bloque(clave, 0, nonce)[:32]


def _calcular_tag(clave_poly: bytes, aad: bytes, texto_cifrado: bytes) -> bytes:
    datos_a_autenticar = (
        aad + _relleno(aad)
        + texto_cifrado + _relleno(texto_cifrado)
        + struct.pack("<QQ", len(aad), len(texto_cifrado))
    )
    return poly1305(clave_poly, datos_a_autenticar)


def cifrar(clave: bytes, nonce: bytes, texto_plano: bytes, aad: bytes = b"") -> tuple:
    """Devuelve (texto_cifrado, tag). El cifrado empieza en el contador 1."""
    clave_poly = _clave_poly1305(clave, nonce)
    texto_cifrado = chacha20.cifrar(clave, 1, nonce, texto_plano)
    return texto_cifrado, _calcular_tag(clave_poly, aad, texto_cifrado)


def descifrar(clave: bytes, nonce: bytes, texto_cifrado: bytes, tag: bytes,
              aad: bytes = b"") -> bytes:
    """Verifica el tag ANTES de descifrar; si no coincide, lanza EtiquetaInvalida."""
    clave_poly = _clave_poly1305(clave, nonce)
    esperado = _calcular_tag(clave_poly, aad, texto_cifrado)
    # compare_digest evita ataques de temporización al comparar los tags.
    if not hmac.compare_digest(esperado, tag):
        raise EtiquetaInvalida("Autenticación fallida: contraseña incorrecta o archivo alterado")
    return chacha20.cifrar(clave, 1, nonce, texto_cifrado)
