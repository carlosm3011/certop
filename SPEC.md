# CERTOP 

## Requerimientos

Una herramienta que permite verificar el estado de certificados TLS en una lista de servidores, incluyendo fecha de expiración, nombre del emisor, lista de algoritmos soportados, etc.

Funciona o bien en el sentido de "top" o "mtr", con una pantalla basada en ncurses que se refresca periódicamente cada N segundos o corre por unica vez y produce un reorte.

La lista de nombres de host / ips y grupos se ingresa en en un archivo TOML similar al archivo de hosts de Ansible, el numero es el puerto tcp. Ver ejemplo:

```
```TOML
[frontends]
  rpki-fe-1.lacnic.net 443
  rpki-fe-2.lacnic.net 443

[rpki-load-balancers]
  lb-rpki-1.lacnic.net 443
  lb-rpki-2.lacnic.net 443
  lb-rpki-3.lacnic.net 443

[email]
  mail.lacnic.net 993
  mail.lacnic.net.uy 993
  mail.lacnic.net.uy 465
```

La salida en modo repeticion debe ser una tabla:

grupo | host | puerto | estado del socket tcp | expiracion del cert | emisor | 

Los flags, en principio son:

./certbot [--once|-1] [--refresh|-r N] [--help]] 

--once    : run once and exit
--refresh : refresh every N seconds, top/mtr style 

## Stack

Let's use Go. Create also a Makefile for easy building. Create targets for amd64 and arm, default to build both. 
