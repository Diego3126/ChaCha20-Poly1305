"""Interfaz de línea de comandos.

Uso:
    python -m chacha_cifrador cifrar   secreto.txt
    python -m chacha_cifrador descifrar secreto.txt.chacha
    python -m chacha_cifrador explicar            # muestra el algoritmo paso a paso
"""

import argparse
import getpass
import os
import sys

from . import chacha20
from .aead import EtiquetaInvalida
from .archivos import FormatoInvalido, cifrar_archivo, descifrar_archivo

EXTENSION = ".chacha"


def _pedir_contrasena(args, confirmar: bool) -> str:
    if args.contrasena is not None:
        return args.contrasena
    contrasena = getpass.getpass("Contraseña: ")
    if confirmar and getpass.getpass("Repite la contraseña: ") != contrasena:
        sys.exit("Error: las contraseñas no coinciden")
    if not contrasena:
        sys.exit("Error: la contraseña no puede estar vacía")
    return contrasena


def _verificar_salida(ruta: str, forzar: bool) -> None:
    if os.path.exists(ruta) and not forzar:
        sys.exit(f"Error: '{ruta}' ya existe (usa --forzar para sobrescribir)")


def comando_cifrar(args) -> None:
    if not os.path.isfile(args.archivo):
        sys.exit(f"Error: no existe el archivo '{args.archivo}'")
    destino = args.salida or args.archivo + EXTENSION
    _verificar_salida(destino, args.forzar)
    contrasena = _pedir_contrasena(args, confirmar=args.contrasena is None)
    cifrar_archivo(args.archivo, destino, contrasena)
    print(f"Archivo cifrado: {destino}")


def comando_descifrar(args) -> None:
    if not os.path.isfile(args.archivo):
        sys.exit(f"Error: no existe el archivo '{args.archivo}'")
    if args.salida:
        destino = args.salida
    elif args.archivo.endswith(EXTENSION):
        destino = args.archivo[: -len(EXTENSION)]
    else:
        destino = args.archivo + ".descifrado"
    _verificar_salida(destino, args.forzar)
    contrasena = _pedir_contrasena(args, confirmar=False)
    try:
        descifrar_archivo(args.archivo, destino, contrasena)
    except (EtiquetaInvalida, FormatoInvalido) as error:
        sys.exit(f"Error: {error}")
    print(f"Archivo descifrado: {destino}")


def _mostrar_matriz(titulo: str, estado: list) -> None:
    print(f"\n{titulo}")
    for fila in range(4):
        print("  " + " ".join(f"{estado[fila * 4 + col]:08x}" for col in range(4)))


def comando_explicar(_args) -> None:
    """Demostración visual para el video: el estado de ChaCha20 paso a paso."""
    clave = bytes(range(32))
    nonce = bytes.fromhex("000000090000004a00000000")
    print("ChaCha20 paso a paso (clave 00..1f, contador 1, nonce de ejemplo del RFC 8439)")

    inicial = chacha20.estado_inicial(clave, 1, nonce)
    _mostrar_matriz("1) Estado inicial (constantes, clave, contador, nonce):", inicial)

    e = list(inicial)
    chacha20.cuarto_de_ronda(e, 0, 4, 8, 12)
    _mostrar_matriz("2) Tras UN quarter round sobre la columna 0 (a, b, c, d = 0, 4, 8, 12):", e)

    mezclado = chacha20.aplicar_rondas(inicial)
    _mostrar_matriz("3) Tras las 20 rondas completas:", mezclado)

    final = [(m + i) & chacha20.MASCARA_32 for m, i in zip(mezclado, inicial)]
    _mostrar_matriz("4) Suma con el estado inicial (esto es el keystream):", final)

    mensaje = b"Hola, mundo!"
    keystream = chacha20.bloque(clave, 1, nonce)
    cifrado = bytes(a ^ b for a, b in zip(mensaje, keystream))
    print("\n5) Cifrado por XOR con el keystream:")
    print(f"  mensaje   : {mensaje.hex()}  ({mensaje.decode()})")
    print(f"  keystream : {keystream[:len(mensaje)].hex()}")
    print(f"  cifrado   : {cifrado.hex()}")
    recuperado = bytes(a ^ b for a, b in zip(cifrado, keystream))
    print(f"  XOR de nuevo con el keystream: {recuperado.decode()}")


def construir_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="chacha_cifrador",
        description="Cifra y descifra archivos con ChaCha20-Poly1305 (implementación educativa).",
    )
    sub = parser.add_subparsers(dest="comando", required=True)

    for nombre, funcion, ayuda in (
        ("cifrar", comando_cifrar, "Cifra un archivo con una contraseña"),
        ("descifrar", comando_descifrar, "Descifra un archivo .chacha"),
    ):
        p = sub.add_parser(nombre, help=ayuda)
        p.add_argument("archivo", help="Archivo de entrada")
        p.add_argument("-o", "--salida", help="Archivo de salida (opcional)")
        p.add_argument("-p", "--contrasena",
                       help="Contraseña (si se omite, se pide de forma oculta; "
                            "pasarla aquí queda en el historial de la terminal)")
        p.add_argument("--forzar", action="store_true", help="Sobrescribir si el destino existe")
        p.set_defaults(funcion=funcion)

    p = sub.add_parser("explicar", help="Muestra ChaCha20 paso a paso (para la demostración)")
    p.set_defaults(funcion=comando_explicar)
    return parser


def main(argv=None) -> None:
    args = construir_parser().parse_args(argv)
    args.funcion(args)


if __name__ == "__main__":
    main()
