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
| `--warn-days N` | desactivado | exit code 2 si algo falla o expira en menos de N dias |
| `--probe-always` | | resondea las versiones TLS en cada refresco |
| `--workers N` | `32` | chequeos concurrentes |
| `--timeout D` | `5s` | timeout por destino |

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
`--warn-days`, algun destino inalcanzable o por vencer.

## Costo de los sondeos

Determinar la matriz de versiones cuesta ~5 handshakes por destino, contra 1 del
chequeo de certificado. Por eso se sondea una sola vez y se cachea: los
refrescos posteriores solo re-chequean socket y expiracion. `--probe-always`
reconstruye la matriz en cada ciclo, y la tecla `p` fuerza un re-sondeo puntual.
