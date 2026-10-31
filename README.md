# ChaCha20-Poly1305 Cifrador

Herramienta de línea de comandos en Python para **cifrar y descifrar archivos con contraseña**, con el algoritmo **ChaCha20-Poly1305** implementado desde cero, siguiendo el [RFC 8439](https://www.rfc-editor.org/rfc/rfc8439).

Proyecto académico hecho por Diego Fernando España Valderrama y Santiago Gonzalez Gómez.

> **Aviso:** es una implementación educativa. Para proteger datos reales usa librerías auditadas como [libsodium](https://github.com/jedisct1/libsodium) o [`cryptography`](https://github.com/pyca/cryptography). En este proyecto `cryptography` solo se usa en las pruebas, como referencia para comparar resultados.

## ¿Por qué ChaCha20-Poly1305?

Es un cifrado moderno diseñado por Daniel J. Bernstein, usado hoy en TLS 1.3, WireGuard, SSH, Signal y Google Chrome. Frente a AES tiene dos ventajas prácticas:

- Solo usa sumas, rotaciones y XOR sobre enteros de 32 bits (diseño **ARX**), por lo que es rápido en cualquier procesador, incluso sin aceleración por hardware.
- Es **cifrado autenticado (AEAD)**: no solo oculta el contenido, también detecta cualquier modificación.

## Cómo funciona

Son dos piezas que trabajan juntas:

### 1. ChaCha20 (confidencialidad)

Es un **cifrado de flujo**: genera un *keystream* pseudoaleatorio y lo combina con el mensaje mediante XOR.

1. Se arma una matriz de 4×4 palabras de 32 bits:

```
 constante  constante  constante  constante
 clave      clave      clave      clave
 clave      clave      clave      clave
 contador   nonce      nonce      nonce
```

2. Se aplican **20 rondas** de la función *quarter round*, alternando columnas y diagonales. Cada quarter round mezcla cuatro palabras (`a, b, c, d`):

```
a += b;  d ^= a;  d <<<= 16
c += d;  b ^= c;  b <<<= 12
a += b;  d ^= a;  d <<<= 8
c += d;  b ^= c;  b <<<= 7
```

3. Al resultado se le suma el estado inicial (sin este paso el proceso sería reversible) y se obtienen **64 bytes de keystream**.
4. Se cifra con `texto_cifrado = texto_plano XOR keystream`. Descifrar es exactamente la misma operación.
5. Para mensajes largos se incrementa el contador y se genera un bloque nuevo cada 64 bytes.

### 2. Poly1305 (integridad y autenticidad)

Calcula una etiqueta de 16 bytes (*tag*) con aritmética módulo el primo `2^130 - 5`. El primer bloque de ChaCha20 (contador 0) se usa para generar la clave de un solo uso de Poly1305. Al descifrar, el tag se verifica **antes** de entregar nada: si la contraseña es incorrecta o el archivo fue alterado, se rechaza.

## Formato del archivo cifrado

```
+--------+-----------+-----------+----------------+-----------+
| "CHA1" | salt (16) | nonce(12) | texto cifrado  | tag (16)  |
+--------+-----------+-----------+----------------+-----------+
```

- La **contraseña** se convierte en una clave de 256 bits con **scrypt** (lento a propósito, para dificultar los ataques de fuerza bruta). El `salt` es aleatorio por archivo.
- El **nonce** es aleatorio por archivo, de modo que cifrar dos veces el mismo contenido da resultados distintos.
- La cabecera viaja como *datos asociados*: no está cifrada, pero queda autenticada por el tag.

## Instalación y uso

Requiere Python 3.6 o superior. El proyecto **no tiene dependencias**; solo usa la biblioteca estándar.

```bash
git clone https://github.com/Diego3126/ChaCha20-Poly1305.git
cd chacha-cifrador
```

**Cifrar** (pide la contraseña de forma oculta):

```bash
python -m chacha_cifrador cifrar secreto.txt
# crea secreto.txt.chacha
```

**Descifrar:**

```bash
python -m chacha_cifrador descifrar secreto.txt.chacha
# recrea secreto.txt
```

**Ver el algoritmo paso a paso** (matriz de estado, un quarter round, 20 rondas, XOR):

```bash
python -m chacha_cifrador explicar
```

Opciones útiles: `-o ARCHIVO` para elegir la salida, `-p CONTRASEÑA` para pasarla por parámetro (queda en el historial de la terminal, úsalo solo para pruebas) y `--forzar` para sobrescribir un archivo existente.

También se puede usar como librería:

```python
from chacha_cifrador.archivos import cifrar_bytes, descifrar_bytes

cifrado = cifrar_bytes(b"mensaje secreto", "mi contraseña")
print(descifrar_bytes(cifrado, "mi contraseña"))
```

## Pruebas

```bash
python -m unittest discover -s tests -v
```

Las pruebas comprueban:

- Los **vectores de prueba oficiales del RFC 8439** para ChaCha20 (2.3.2), Poly1305 (2.5.2) y el AEAD completo (2.8.2).
- Que el resultado coincide byte a byte con la librería `cryptography` en distintos tamaños de mensaje (opcional: `pip install cryptography`).
- Ida y vuelta de archivos, contraseña incorrecta, archivos modificados (en cabecera, cuerpo o tag) y formato inválido.

## Estructura del proyecto

```
chacha_cifrador/
├── chacha20.py   # quarter round, bloque de 64 bytes y cifrado por XOR
├── poly1305.py   # código de autenticación de mensajes
├── aead.py       # ChaCha20-Poly1305 (RFC 8439, sección 2.8)
├── archivos.py   # formato del archivo, scrypt y cifrado de archivos
└── cli.py        # interfaz de línea de comandos
tests/
└── test_chacha.py
```

## Limitaciones

- Implementación en Python puro: es lenta (del orden de 1 MB por segundo) y no está hecha para resistir ataques de canal lateral (no es de tiempo constante).
- Cada archivo se carga completo en memoria.
- Hay que elegir contraseñas largas: la seguridad real depende de ellas.

## Referencias

- [RFC 8439: ChaCha20 and Poly1305 for IETF Protocols](https://www.rfc-editor.org/rfc/rfc8439)
- D. J. Bernstein, [*ChaCha, a variant of Salsa20*](https://cr.yp.to/chacha/chacha-20080128.pdf)
- D. J. Bernstein, [*The Poly1305-AES message-authentication code*](https://cr.yp.to/mac/poly1305-20050329.pdf)
- [RFC 7914: scrypt](https://www.rfc-editor.org/rfc/rfc7914)

## Licencia

MIT. Ver [LICENSE](LICENSE).
