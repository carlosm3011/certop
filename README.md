# CERTOP

Visualizar estado de certificados en una flota de servidores.

CERTOP toma un inventario de destinos y, para **cada direccion IP** de cada uno,
reporta el estado del socket TCP, la expiracion y el emisor del certificado, su
validez, y que versiones de TLS acepta el servidor. Corre en una pasada unica
(reporte para cron o monitoreo) o en una pantalla que se refresca estilo
`top`/`mtr`.

## Instalar

```sh
go install github.com/carlosm3011/certop/cmd/certop@latest
```

Requiere Go 1.27 o superior, y funciona desde la version 1.3.0: los tags
anteriores declaran otro module path y `go install` los rechaza. Tambien hay
binarios ya compilados para linux/amd64 y darwin/arm64 en cada
[release](https://github.com/carlosm3011/certop/releases).

## Compilar

```sh
make          # compila para linux/amd64 y darwin/arm64 (Apple Silicon) en dist/
make build    # compila para la plataforma local
make check    # go vet + go test
make help     # lista todos los targets
```

Los binarios salen estaticos (`CGO_ENABLED=0`).

## Inventario

Un archivo TOML al estilo del inventario de Ansible: cada tabla es un grupo y su
clave `hosts` lista los destinos. Por defecto se lee `./hosts.toml`; ver
[`hosts.toml.example`](hosts.toml.example).

```toml
[rpki-frontends]
# Los nodos estan detras de un CNAME: el certificado sirve la identidad del
# servicio, no la del nodo.
expect = "rrdp.lacnic.net"
hosts = [
  "fe-1.rrdp.lacnic.net:443",
  "fe-2.rrdp.lacnic.net:443",
]

[email]
hosts = [
  "mail.lacnic.net.uy:993",
  "mail.lacnic.net.uy:465",
  # una entrada puede traer su propio expect y pisar el del grupo:
  { addr = "webmail.lacnic.net:443", expect = "mail.lacnic.net" },
]
```

Una entrada puede escribirse de dos formas:

| Forma | Cuando |
|---|---|
| `"host:puerto"` | el caso normal |
| `{ addr = "host:puerto", expect = "nombre" }` | cuando ese destino necesita un `expect` propio |

Un mismo host puede repetirse con puertos distintos, como `mail.lacnic.net.uy`
arriba: son dos destinos independientes.

### Nombre esperado (`expect`)

Un nodo detras de un CNAME sirve el certificado del servicio y no uno con su
propio nombre: `fe-1.rrdp.lacnic.net` presenta un `*.lacnic.net`, que cubre
`rrdp.lacnic.net` pero no un nombre de segundo nivel. Sin ayuda, CERTOP lo
reporta como `NOMBRE-NO-COINCIDE`, que es ruido: el nodo esta bien configurado.

`expect` fija el nombre que se manda en **SNI** y contra el que se **valida** el
certificado — exactamente lo que hace un cliente real que llega por el CNAME.
Se declara a nivel de grupo, y una entrada puede pisarlo.

### STARTTLS

Los puertos que negocian TLS sobre una sesion en claro se detectan por el
puerto: `25` y `587` hablan `smtp`, `143` `imap`, `110` `pop3`. El resto se
trata como TLS implicito, como antes.

La clave `starttls` pisa esa inferencia, en el grupo o en una entrada:

```toml
[email]
hosts = [
  "mail.lacnic.net:25",                                  # smtp por el puerto
  "mail.lacnic.net.uy:993",                              # implicito
  { addr = "mail.lacnic.net:2525", starttls = "smtp" },  # puerto no estandar
  { addr = "raro.lacnic.net:143",  starttls = "none" },  # forzar implicito
]
```

Si el servidor contesta pero no ofrece STARTTLS — o lo anuncia y despues lo
rechaza — el estado es `SIN-STARTTLS`, que cuenta como problema.

Soportados: `smtp`, `imap`, `pop3` y `none`. PostgreSQL, LDAP, MySQL, XMPP y FTP
no estan.

### IPv4 e IPv6

Cada nombre se chequea en **todas** sus direcciones: una fila por cada registro
A y AAAA. Un config actualizado en una familia y olvidado en la otra solo se ve
chequeando cada direccion por separado.

Consecuencias practicas:

- La cantidad de filas no es la cantidad de entradas del inventario, y puede
  cambiar entre pasadas si cambia el DNS.
- Un literal IP en el inventario no se resuelve: es una sola fila.
- Si el nombre no resuelve queda una fila con `tcp = dns`, en vez de
  desaparecer.

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
certop --once --format table              # tabla legible
certop --once > estado.csv                # CSV para procesar
certop --once --format json | jq '.[] | select(.dias_restantes < 30)'
certop --once --warn-days 30 >/dev/null   # chequeo para cron; exit 2 si hay algo por vencer
certop --refresh 5                        # pantalla que se refresca cada 5s
certop --refresh 5 --warn-days 7          # en pantalla, avisar solo con menos de 7 dias
```

## Salida

```
$ certop --once --format table
GRUPO  HOST                AF  IP                        PUERTO  TCP  EXPIRA  TLS   EMISOR                    ESTADO
email  mail.lacnic.net.uy  4   168.121.184.3             993     ok   160d    -123  DigiCert Global G2 TLS..  OK
email  mail.lacnic.net.uy  6   2001:13c7:7001:110::3     993     ok   160d    -123  DigiCert Global G2 TLS..  OK
email  mail.lacnic.net.uy  4   168.121.184.3             465     ok   160d    --23  DigiCert Global G2 TLS..  OK
email  mail.lacnic.net.uy  6   2001:13c7:7001:110::3     465     ok   160d    --23  DigiCert Global G2 TLS..  OK
web    www.lacnic.net      4   200.3.14.184              443     ok   24d     --23  DigiCert Global G2 TLS..  OK
web    www.lacnic.net      6   2001:13c7:7002:4128::184  443     ok   24d     --23  DigiCert Global G2 TLS..  OK
```

Tres entradas del inventario, seis filas: cada host es dual-stack. En el ejemplo
tambien se ve que el puerto 993 acepta TLS 1.1 (`-123`) y el 465 no (`--23`).

### Columnas

| Columna | Significado |
|---|---|
| `AF` | familia de la direccion chequeada: `4` o `6`, `-` si no se resolvio |
| `IP` | la direccion concreta a la que se conecto |
| `TCP` | `ok`, `rechazado`, `timeout`, `dns`, `error` |
| `EXPIRA` | dias hasta el vencimiento; negativo si ya vencio |
| `TLS` | versiones aceptadas, ver abajo |
| `ESTADO` | resultado de validar el certificado, ver abajo |

El protocolo de STARTTLS usado aparece en CSV y JSON, no en la tabla ni en la
pantalla: el estado `SIN-STARTTLS` ya dice lo que hace falta y los formatos
angostos no dan para otra columna.

En la pantalla de refresco la `IP` aparece solo cuando el ancho de la terminal
alcanza; en CSV y JSON esta siempre.

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
| `NOMBRE-NO-COINCIDE` | el nombre verificado no esta en el certificado — si es un nodo detras de un CNAME, es lo que resuelve [`expect`](#nombre-esperado-expect) |
| `CADENA-INCOMPLETA` | no se pudo construir una cadena confiable |
| `SIN-STARTTLS` | el puerto contesta pero no negocia TLS |
| `ERROR` | fallo el handshake |

### CSV

Es el formato por defecto de `--once`. Columnas, en orden:

```
grupo, host, puerto, af, ip, tcp, expira_utc, dias_restantes, emisor,
estado_cert, tls_negociada, cipher, clave, firma, tls10, tls11, tls12, tls13,
starttls
```

Los campos de certificado quedan vacios (no en cero) cuando no se llego a
obtener uno.

### JSON

Un arreglo de objetos con los mismos datos, con la matriz de versiones anidada
en `tls` (`true` / `false` / `null`) y `expect` presente solo si el destino lo
define.

### Exit codes

`0` todo bien · `1` error de uso, inventario o escritura · `2` con
`--warn-days`, alguna fila inalcanzable o por vencer. Con el chequeo por familia
esto cubre tambien "IPv6 caido, IPv4 bien".

## Modo refresco

`q` salir · `r` refrescar ahora · `p` resondear versiones TLS · `s` cambiar
orden (grupo / host / expiracion) · `espacio` pausar.

El encabezado separa dos categorias, porque no piden la misma reaccion:

- **con problemas** — hay algo roto: destino inalcanzable, sin certificado, o
  certificado invalido (`EXPIRADO`, `SELF-SIGNED`, `NOMBRE-NO-COINCIDE`,
  `CADENA-INCOMPLETA`). Se pintan en rojo.
- **por vencer** — el certificado esta bien, pero vence dentro del umbral
  (30 dias por defecto, o lo que diga `--warn-days`). Se pintan en amarillo, y
  en amarillo resaltado si faltan menos de 7 dias.

```
certop  24 filas  refresco 5s  orden grupo  ultima 15:22:03 (812ms)  24 por vencer (<30d)
```

Las filas se ordenan de forma estable entre pasadas: las direcciones de un mismo
host quedan siempre juntas y en el mismo orden, aunque el DNS rote sus
respuestas.

## Compatibilidad

En 1.0 el CSV gano las columnas `af` e `ip` despues de `puerto`, y el JSON gano
`af`, `ip` y `expect`. Un consumidor que lea las columnas por posicion hay que
ajustarlo; por nombre no cambia nada.

La columna `starttls` se agrego **al final** de la fila del CSV, justamente para
no volver a mover posiciones.

Los inventarios de 0.9.x siguen parseando sin cambios: `expect` y la forma de
tabla inline son opcionales.

## Releases

El repo vive en dos lados: un GitLab interno y el GitHub publico. Una release
sale hacia los dos a la vez y con los **mismos binarios**.

El GitLab interno no tiene runner con Go, asi que los binarios se compilan
**localmente** y se commitean en `release/`; los dos pipelines solo crean el
objeto Release apuntando a esos archivos. GitHub si podria compilarlos, pero
subir los mismos bytes de los dos lados hace que un unico `SHA256SUMS` valga
para ambos y evita la pregunta de cual binario es el bueno.

**No hace falta ningun token**: git viaja por ssh con la misma llave que usas
para pushear, y cada CI usa el token que se inyecta solo (`CI_JOB_TOKEN` en
GitLab, `GITHUB_TOKEN` en Actions).

```sh
VERSION=v1.3.0 make release
```

`make release` hace, en este orden:

1. controles: version en semver de tres numeros, arbol limpio, rama `main`, en
   sincronia con **cada** remoto, y que el tag no exista ni local ni en ninguno
   de ellos;
2. `make dist` y `SHA256SUMS`;
3. copia los tres archivos a `release/` y fija `VERSION` en el Makefile, para
   que un `make build` posterior no siga diciendo la version vieja;
4. commitea, pushea `main` a todos los remotos, y recien ahi crea y pushea el
   tag — eso dispara los dos pipelines.

El orden importa: la release de GitLab enlaza a los archivos del repo en ese
tag, asi que el commit tiene que estar en el remoto antes que el tag. Si alguien
pushea un tag a mano, los dos jobs fallan con un mensaje claro en vez de crear
una release con links rotos o sin binarios.

`REMOTES` pisa la lista de remotos (default `origin github`); los que no esten
configurados se saltean con un aviso, para que un clon con uno solo pueda
liberar igual.

Para ver que haria sin tocar nada:

```sh
VERSION=v1.3.0 make release-dry
```

`VERSION` acepta `1.3.0` o `v1.3.0`; el tag siempre queda como `v1.3.0`. Sin
`VERSION` en el entorno rige el default del Makefile, que apunta a la ultima
release.

Tienen que ser **tres numeros**. El proxy de modulos de Go solo reconoce semver
canonico, asi que un tag `v1.3` existe en el repo pero queda invisible para
`go install` — que es exactamente lo que le paso a `v1.1`. `make release` lo
rechaza antes de compilar nada.

Los binarios quedan versionados en el repo, unos 1.7 MiB por release ya
comprimidos por git. `dist/` sigue ignorado, para que compilar durante el
desarrollo no ensucie el arbol.

Un detalle: el `+sha` que reporta `--version` es el commit **desde el que se
compilo**, no el commit que contiene el binario — no se puede embeber el hash de
un commit que todavia no existe.

## Costo de los sondeos

Determinar la matriz de versiones cuesta ~5 handshakes por destino, contra 1 del
chequeo de certificado. Por eso se sondea una sola vez por direccion y se
cachea: los refrescos posteriores solo re-chequean socket y expiracion.
`--probe-always` reconstruye la matriz en cada ciclo, y la tecla `p` fuerza un
re-sondeo puntual.

## Licencia

BSD 2-Clause. Ver [`LICENSE`](LICENSE).
