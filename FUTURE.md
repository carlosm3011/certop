# CERTOP — ideas para mas adelante

Anotaciones para no perderlas. No estan disenadas ni planificadas todavia.

Cada entrada tiene un identificador estable tipo `FUT-3`, para poder referirse a
ella sin repetir el titulo. Los numeros no se reciclan: si una entrada se
resuelve o se descarta, su numero se retira con ella.

Resueltos: FUT-5 (STARTTLS para smtp, imap y pop3), FUT-7 (tap de Homebrew,
en carlosm3011/homebrew-certop).

## FUT-6 - testear AFs independientemente
Agregar flags -4 y -6 que permitan testear ipv4 o ipv6 separadamente, pero manteniendo el default en testear ambas igual que ahora.

## FUT-8 - macOS bloquea el binario: "desarrollador desconocido"

El binario `darwin/arm64` lleva solo la firma ad-hoc que el linker de Go aplica
por defecto (`codesign -dvvv` reporta `flags=0x20002(adhoc,linker-signed)`), no
un Developer ID. `spctl -a -t execute` lo rechaza, asi que Gatekeeper lo bloquea
en cualquier Mac que lo reciba **con el atributo de cuarentena** — que lo pone
el navegador que lo descarga, y no `curl`.

Mitigado desde 1.3.0 documentando la descarga por `curl` y el `xattr -d` de
respaldo (README, seccion Instalar), y sobre todo por el tap de Homebrew, que
compila desde la fuente: el binario que instala `brew` queda igual de ad-hoc
firmado, pero sin atributo de cuarentena, asi que Gatekeeper ni lo evalua.

Lo que queda pendiente cuesta plata: firmar con un **Developer ID Application** y
notarizar. Son USD 99/ano de Apple Developer Program, que hoy no tenemos. Notas
para cuando se decida:

- `codesign --timestamp --options runtime` y despues `xcrun notarytool submit`.
- Un Mach-O suelto **no se puede estaplar**: `stapler` solo acepta `.dmg`, `.pkg`
  o `.app`. Un `certop-darwin-arm64` pelado, aun notarizado, necesita consulta en
  linea a Apple en la primera corrida, y sigue bloqueado en una maquina sin red.
  Resolverlo de verdad implica publicar un contenedor en vez del binario suelto,
  y eso cambia que hay en `release/` y que cubre el `SHA256SUMS`.
- La firma iria en `scripts/release.sh`, que ya compila local: el certificado
  queda en esta Mac y la CI sigue sin necesitar ningun token.
- No hay binario `darwin/amd64`. Las Mac Intel hoy solo tienen `go install`, el
  tap, o compilar a mano.

## FUT-1 — `--init`: generar un hosts.toml de arranque

Un flag que cree un `hosts.toml` por defecto, con algun destino conocido como
`www.google.com` para que la herramienta muestre algo util en la primera corrida
sin tener que armar el inventario a mano.

## FUT-2 — `--influx`: salida en line protocol de InfluxDB

Un flag que emita los resultados en el line protocol de InfluxDB, para graficar
y monitorear automaticamente. Corre una sola vez: sin refresco ni ncurses.

# Pendientes conocidos

Cosas que quedaron identificadas y sin resolver mientras se construia 1.0.

## FUT-3 — El exit code ignora los problemas de certificado

`report.ExitCode` dispara solo por destino inalcanzable o por vencimiento
dentro de `--warn-days`. Un certificado autofirmado, con el nombre que no
coincide o con la cadena rota, pero con meses por delante, termina en exit `0`.
La pantalla lo cuenta como problema y cron no se entera: son dos criterios
distintos para lo mismo. `probe.Result.Severity` ya tiene la clasificacion; se
trata de pasar `ExitCode` por ahi. Cambia el comportamiento de cualquier chequeo
automatico que ya este corriendo.

## FUT-4 — Las columnas van en distinto orden segun el formato

La tabla y la pantalla muestran `HOST AF IP PUERTO`; el CSV y el JSON usan
`host, puerto, af, ip`. Alinear la tabla y la pantalla al orden del CSV es
cosmetico y no rompe nada; tocar el CSV seria un segundo cambio incompatible
despues del de 1.0.
