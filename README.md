# CERTOP

Visualizar estado de certificados en una flota de servidores.

CERTOP chequea, para cada destino de un inventario, el estado del socket TCP, la
expiracion y el emisor del certificado, su validez, y que versiones de TLS
acepta el servidor. Corre en una pasada unica (reporte para cron o monitoreo) o
en una pantalla que se refresca estilo `top`/`mtr`.

## Compilar

```sh
make          # compila para linux/amd64 y darwin/arm64 (Apple Silicon) en dist/
make build    # compila para la plataforma local
make check    # go vet + go test
make help     # lista todos los targets
```

Requiere Go 1.27 o superior. Los binarios salen estaticos (`CGO_ENABLED=0`).

## Inventario

Un archivo TOML al estilo del inventario de Ansible: cada tabla es un grupo y su
clave `hosts` lista los destinos en formato `host:puerto`. Ver
[`hosts.toml.example`](hosts.toml.example).

```toml
[frontends]
hosts = [
  "rpki-fe-1.lacnic.net:443",
  "rpki-fe-2.lacnic.net:443",
]

[email]
hosts = [
  "mail.lacnic.net.uy:993",
  "mail.lacnic.net.uy:465",
]
```

Un mismo host puede repetirse con puertos distintos. Solo se soporta TLS
implicito (443, 465, 993, ...); no hay STARTTLS.

### Nombre esperado (`expect`)

Un nodo detras de un CNAME sirve el certificado del servicio, no uno con su
propio nombre, y por eso da `NOMBRE-NO-COINCIDE`. `expect` fija el nombre que se
manda en SNI y contra el que se valida el certificado — lo mismo que ve un
cliente real que llega por el CNAME:

```toml
[rpki-frontends]
expect = "rrdp.lacnic.net"
hosts = [
  "fe-172-233-162-16.rrdp.lacnic.net:443",
  # una entrada puede pisar el expect del grupo:
  { addr = "otro.lacnic.net:443", expect = "www.lacnic.net" },
]
```

### IPv4 e IPv6

Cada nombre se chequea en **todas** sus direcciones: una fila por cada registro A
y AAAA. Asi se detecta el caso de un config actualizado en una familia y olvidado
en la otra. La columna `AF` vale `4` o `6`.

## Uso

```
certop [--once|-1] [--refresh|-r N] [--file|-f RUTA] [--format csv|table|json]
       [--warn-days N] [--probe-always] [--workers N] [--timeout D] [--help]
```

| Flag | Default | Descripcion |
|---|---|---|
| `--once`, `-1` | | corre una sola vez y termina (modo por defecto) |
| `--refresh`, `-r N` | | refresca cada N segundos, estilo top/mtr |
| `--file`, `-f` | `hosts.toml` | archivo de inventario |
| `--format` | `csv` | formato de `--once`: `csv`, `table` o `json` |
| `--warn-days N` | `30` en pantalla | umbral de "por vencer"; con `--once` ademas da exit code 2 |
| `--probe-always` | | resondea las versiones TLS en cada refresco |
| `--workers N` | `32` | chequeos concurrentes |
| `--timeout D` | `5s` | timeout por destino (incluye la resolucion) |

### Ejemplos

```sh
certop --once --format table            # tabla legible
certop --once > estado.csv              # CSV para procesar
certop --once --format json | jq '.[] | select(.dias_restantes < 30)'
certop --once --warn-days 30 >/dev/null # chequeo para cron; exit 2 si hay algo por vencer
certop --refresh 5                      # pantalla que se refresca cada 5s
```

### Teclas en modo refresco

`q` salir · `r` refrescar ahora · `p` resondear versiones TLS · `s` cambiar
orden (grupo / host / expiracion) · `espacio` pausar.

### Problemas y avisos

El encabezado de la pantalla separa dos categorias, porque no piden la misma
reaccion:

- **con problemas** — hay algo roto: destino inalcanzable, sin certificado, o
  certificado invalido (`EXPIRADO`, `SELF-SIGNED`, `NOMBRE-NO-COINCIDE`,
  `CADENA-INCOMPLETA`). Se pintan en rojo.
- **por vencer** — el certificado esta bien, pero vence dentro del umbral
  (30 dias por defecto, o lo que diga `--warn-days`). Se pintan en amarillo, y
  en amarillo resaltado si faltan menos de 7 dias.

```
certop  24 filas  refresco 5s  orden grupo  ultima 15:22:03 (812ms)  24 por vencer (<30d)
```

### Columnas AF e IP

`AF` es la familia de la direccion chequeada (`4` o `6`) y `IP` la direccion
concreta. En la pantalla de refresco la IP aparece cuando el ancho de la terminal
alcanza; en CSV y JSON estan siempre.

### Columna TLS

Cuatro posiciones, una por version en orden 1.0/1.1/1.2/1.3: el digito si el
servidor la acepta, `-` si la rechaza, `?` si no se pudo determinar. `--23`
significa que rechaza 1.0 y 1.1 y acepta 1.2 y 1.3.

### Estados del certificado

El handshake se hace sin verificar la cadena, para que un host con certificado
invalido igual reporte expiracion y emisor. La validacion se corre aparte:

| Estado | Significado |
|---|---|
| `OK` | valida contra las raices del sistema |
| `EXPIRADO` | vencido, o todavia no valido |
| `SELF-SIGNED` | autofirmado |
| `NOMBRE-NO-COINCIDE` | el nombre del destino no esta en el certificado |
| `CADENA-INCOMPLETA` | no se pudo construir una cadena confiable |
| `ERROR` | fallo el handshake |

### Exit codes

`0` todo bien · `1` error de uso, inventario o escritura · `2` con
`--warn-days`, alguna fila inalcanzable o por vencer. Con el chequeo por familia
esto cubre tambien "IPv6 caido, IPv4 bien".

## Compatibilidad

En 1.0 el CSV gano las columnas `af` e `ip` despues de `puerto`, y el JSON gano
`af`, `ip` y `expect`. Cualquier consumidor que lea las columnas por posicion hay
que ajustarlo; por nombre no cambia nada.

## Costo de los sondeos

Determinar la matriz de versiones cuesta ~5 handshakes por destino, contra 1 del
chequeo de certificado. Por eso se sondea una sola vez y se cachea: los
refrescos posteriores solo re-chequean socket y expiracion. `--probe-always`
reconstruye la matriz en cada ciclo, y la tecla `p` fuerza un re-sondeo puntual.
