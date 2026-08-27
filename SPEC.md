# CERTOP 

## Requerimientos

Una herramienta que permite verificar el estado de certificados TLS en una lista de servidores, incluyendo fecha de expiración, nombre del emisor, lista de algoritmos soportados, etc.

Funciona o bien en el sentido de "top" o "mtr", con una pantalla basada en ncurses que se refresca periódicamente cada N segundos o corre por unica vez y produce un reorte.

La lista de nombres de host / ips y grupos se ingresa en un archivo TOML similar al archivo de hosts de Ansible. Cada tabla es un grupo y su clave `hosts` es la lista de destinos en formato `host:puerto`. Ver ejemplo:

```toml
[frontends]
hosts = [
  "rpki-fe-1.lacnic.net:443",
  "rpki-fe-2.lacnic.net:443",
]

[rpki-load-balancers]
hosts = [
  "lb-rpki-1.lacnic.net:443",
  "lb-rpki-2.lacnic.net:443",
  "lb-rpki-3.lacnic.net:443",
]

[email]
hosts = [
  "mail.lacnic.net:993",
  "mail.lacnic.net.uy:993",
  "mail.lacnic.net.uy:465",
]
```

Un mismo host puede aparecer varias veces con puertos distintos (ver `mail.lacnic.net.uy`). El formato `host:puerto` es el que consume directamente `net.Dial` en Go.

La salida en modo repeticion debe ser una tabla:

grupo | host | puerto | estado del socket tcp | expiracion del cert | emisor | estado del cert |

Los flags son:

./certop [--once|-1] [--refresh|-r N] [--file|-f RUTA] [--format csv|table|json]
         [--warn-days N] [--probe-always] [--help]

--once         : run once and exit
--refresh      : refresh every N seconds, top/mtr style
--file         : inventario TOML (por defecto ./hosts.toml)
--format       : formato de salida en modo --once (por defecto csv)
--warn-days    : umbral de dias para el exit code (ver abajo)
--probe-always : re-probar versiones TLS en cada refresco (ver abajo)

## Versiones y algoritmos TLS

Para cada destino se reporta:

- la version TLS y el cipher suite efectivamente negociados,
- el tipo y tamaño de clave del certificado y su algoritmo de firma,
- la matriz de versiones aceptadas (TLS 1.0 / 1.1 / 1.2 / 1.3), que requiere un
  handshake adicional por version.

Para sondear TLS 1.0/1.1 el cliente ofrece explicitamente todas las suites que
implementa `crypto/tls`, incluidas las obsoletas (RSA-kex, 3DES): la lista por
defecto de Go las omite y sin ellas un servidor viejo se reportaria como si
rechazara la version. Go 1.27 elimino los GODEBUG `tls10server`, `tlsrsakex` y
`tls3des`, pero las suites siguen implementadas y ofrecerlas por `CipherSuites`
alcanza; lo unico que se perdio es la posibilidad de *servir* TLS 1.0/1.1.

La matriz de versiones cuesta ~5 handshakes por destino, por lo que **por defecto se
prueba una sola vez** (primer ciclo) y se cachea; los refrescos posteriores solo
re-chequean el socket TCP y la expiracion del certificado, con un handshake por
destino. Se puede forzar un re-sondeo desde la interfaz, y `--probe-always` vuelve a
construir la matriz completa en cada refresco.

## Validacion de certificados

El handshake se hace sin verificar la cadena, de modo que el certificado hoja se
obtiene siempre; la validacion se corre aparte y su resultado se muestra como una
columna de estado (`OK`, `EXPIRADO`, `SELF-SIGNED`, `NOMBRE NO COINCIDE`, `CADENA
INCOMPLETA`, ...). Un host con certificado invalido igual muestra expiracion y emisor
— suele ser justamente el host por el que se abrio la herramienta.

## Salida y exit code

En modo `--once` la salida por defecto es CSV a stdout. `--format table` produce una
tabla alineada legible y `--format json` una estructura anidada (mas comoda para la
matriz de versiones, que en CSV hay que aplanar en columnas).

Con `--warn-days N` el proceso termina con exit code distinto de cero si algun destino
es inalcanzable o expira dentro de N dias, para poder usarlo desde cron o desde un
chequeo de monitoreo sin parsear la salida.

## Stack

Go 1.27 o superior. El Makefile compila por defecto para linux/amd64 y linux/arm64;
`make build` genera el binario de la plataforma local y `make check` corre vet y pruebas.

La pantalla de refresco se implementa sobre **tcell**, manejando directamente el buffer
de pantalla, el layout, los eventos de resize y el loop de teclado.
