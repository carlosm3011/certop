# CERTOP — ideas para mas adelante

Anotaciones para no perderlas. No estan disenadas ni planificadas todavia.

Cada entrada tiene un identificador estable tipo `FUT-3`, para poder referirse a
ella sin repetir el titulo. Los numeros no se reciclan: si una entrada se
resuelve o se descarta, su numero se retira con ella.

Resueltos: FUT-5 (STARTTLS para smtp, imap y pop3).

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
