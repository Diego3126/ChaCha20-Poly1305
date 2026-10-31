"""Pruebas con los vectores oficiales del RFC 8439 y pruebas de la herramienta.

Ejecutar desde la raíz del proyecto:
    python -m unittest discover -s tests -v
"""

import os
import tempfile
import unittest

from chacha_cifrador import aead, archivos, chacha20
from chacha_cifrador.poly1305 import poly1305

try:
    from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
except ImportError:  # la comparación con la librería es opcional
    ChaCha20Poly1305 = None


class VectoresRFC8439(unittest.TestCase):
    def test_bloque_chacha20_seccion_2_3_2(self):
        clave = bytes(range(32))
        nonce = bytes.fromhex("000000090000004a00000000")
        esperado = bytes.fromhex(
            "10f1e7e4d13b5915500fdd1fa32071c4"
            "c7d1f4c733c068030422aa9ac3d46c4e"
            "d2826446079faa0914c2d705d98b02a2"
            "b5129cd1de164eb9cbd083e8a2503c4e"
        )
        self.assertEqual(chacha20.bloque(clave, 1, nonce), esperado)

    def test_poly1305_seccion_2_5_2(self):
        clave = bytes.fromhex(
            "85d6be7857556d337f4452fe42d506a8"
            "0103808afb0db2fd4abff6af4149f51b"
        )
        mensaje = b"Cryptographic Forum Research Group"
        self.assertEqual(
            poly1305(clave, mensaje).hex(), "a8061dc1305136c6c22b8baf0c0127a9"
        )

    def test_aead_seccion_2_8_2(self):
        texto = (
            b"Ladies and Gentlemen of the class of '99: If I could offer you "
            b"only one tip for the future, sunscreen would be it."
        )
        aad = bytes.fromhex("50515253c0c1c2c3c4c5c6c7")
        clave = bytes(range(0x80, 0xA0))
        nonce = bytes.fromhex("070000004041424344454647")
        cifrado, tag = aead.cifrar(clave, nonce, texto, aad)
        self.assertEqual(cifrado[:16].hex(), "d31a8d34648e60db7b86afbc53ef7ec2")
        self.assertEqual(tag.hex(), "1ae10b594f09e26a7e902ecbd0600691")
        self.assertEqual(aead.descifrar(clave, nonce, cifrado, tag, aad), texto)


@unittest.skipIf(ChaCha20Poly1305 is None, "librería 'cryptography' no instalada")
class ComparacionConLibreria(unittest.TestCase):
    def test_coincide_con_cryptography_en_varios_tamanos(self):
        for tamano in (0, 1, 15, 16, 17, 63, 64, 65, 1000, 4096):
            clave, nonce = os.urandom(32), os.urandom(12)
            datos, aad = os.urandom(tamano), os.urandom(7)
            cifrado, tag = aead.cifrar(clave, nonce, datos, aad)
            referencia = ChaCha20Poly1305(clave).encrypt(nonce, datos, aad)
            self.assertEqual(cifrado + tag, referencia, f"tamaño {tamano}")


class Archivos(unittest.TestCase):
    def test_ida_y_vuelta(self):
        datos = os.urandom(5000)
        self.assertEqual(
            archivos.descifrar_bytes(archivos.cifrar_bytes(datos, "clave123"), "clave123"),
            datos,
        )

    def test_contrasena_incorrecta(self):
        cifrado = archivos.cifrar_bytes(b"secreto", "correcta")
        with self.assertRaises(aead.EtiquetaInvalida):
            archivos.descifrar_bytes(cifrado, "incorrecta")

    def test_detecta_modificaciones_en_cualquier_parte(self):
        cifrado = bytearray(archivos.cifrar_bytes(b"mensaje importante", "clave"))
        # cabecera (salt/nonce), cuerpo y tag
        for posicion in (6, 25, 35, len(cifrado) - 1):
            alterado = bytearray(cifrado)
            alterado[posicion] ^= 0x01
            with self.assertRaises(aead.EtiquetaInvalida, msg=f"byte {posicion}"):
                archivos.descifrar_bytes(bytes(alterado), "clave")

    def test_formato_invalido(self):
        with self.assertRaises(archivos.FormatoInvalido):
            archivos.descifrar_bytes(b"esto no es un archivo cifrado" * 3, "clave")

    def test_dos_cifrados_del_mismo_mensaje_son_distintos(self):
        a = archivos.cifrar_bytes(b"igual", "clave")
        b = archivos.cifrar_bytes(b"igual", "clave")
        self.assertNotEqual(a, b)  # salt y nonce aleatorios

    def test_archivo_en_disco(self):
        with tempfile.TemporaryDirectory() as carpeta:
            original = os.path.join(carpeta, "nota.txt")
            cifrado = original + ".chacha"
            recuperado = os.path.join(carpeta, "recuperado.txt")
            with open(original, "wb") as f:
                f.write("Cifrado con ñ y tildes: ¡funciona!".encode("utf-8"))
            archivos.cifrar_archivo(original, cifrado, "clave")
            archivos.descifrar_archivo(cifrado, recuperado, "clave")
            with open(original, "rb") as a, open(recuperado, "rb") as b:
                self.assertEqual(a.read(), b.read())


if __name__ == "__main__":
    unittest.main()
