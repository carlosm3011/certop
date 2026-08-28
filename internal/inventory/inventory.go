// Package inventory lee el archivo TOML de inventario y lo aplana en una lista
// de destinos a chequear.
package inventory

import (
	"fmt"
	"net"
	"os"
	"slices"
	"sort"
	"strconv"

	"github.com/pelletier/go-toml/v2"
)

// Target es un destino individual: un host y un puerto dentro de un grupo.
type Target struct {
	Group string
	Host  string
	Port  string
	// Addr es "host:puerto", el destino tal como se escribio.
	Addr string
	// Expect es el nombre que se espera que sirva el destino, para los nodos
	// que estan detras de un CNAME y cuyo certificado nunca lleva su propio
	// nombre. Vacio significa "el mismo host".
	Expect string
	// StartTLS es el protocolo con el que hay que negociar TLS sobre una
	// sesion en claro ("smtp", "imap", "pop3"). Vacio es TLS implicito.
	StartTLS string
}

// VerifyName es el nombre que se manda en SNI y contra el que se valida el
// certificado.
func (t Target) VerifyName() string {
	if t.Expect != "" {
		return t.Expect
	}
	return t.Host
}

// Protocolos de STARTTLS soportados. "none" fuerza TLS implicito en un puerto
// que de otro modo se inferiria.
const (
	StartTLSSMTP = "smtp"
	StartTLSIMAP = "imap"
	StartTLSPOP3 = "pop3"
	startTLSNone = "none"
)

var startTLSValues = []string{StartTLSSMTP, StartTLSIMAP, StartTLSPOP3, startTLSNone}

// startTLSByPort son los puertos bien conocidos que negocian TLS sobre una
// sesion en claro. Un puerto que no este aca se trata como TLS implicito.
var startTLSByPort = map[string]string{
	"25":  StartTLSSMTP,
	"587": StartTLSSMTP,
	"143": StartTLSIMAP,
	"110": StartTLSPOP3,
}

type group struct {
	// Expect aplica a todas las entradas del grupo que no traigan el suyo.
	Expect string `toml:"expect"`
	// StartTLS aplica a todas las entradas del grupo que no traigan el suyo.
	StartTLS string `toml:"starttls"`
	// Hosts admite dos formas por entrada: "host:puerto", o la tabla inline
	// { addr = "host:puerto", expect = "nombre" }.
	Hosts []any `toml:"hosts"`
}

// Load lee y parsea el inventario en path.
func Load(path string) ([]Target, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return Parse(data)
}

// Parse aplana un inventario TOML en una lista de destinos.
//
// El orden de iteracion de un mapa TOML no esta definido, asi que los grupos se
// ordenan alfabeticamente; dentro de cada grupo se preserva el orden del
// archivo. Un mismo host puede repetirse en puertos distintos.
func Parse(data []byte) ([]Target, error) {
	var groups map[string]group
	if err := toml.Unmarshal(data, &groups); err != nil {
		return nil, fmt.Errorf("inventario invalido: %w", err)
	}

	names := make([]string, 0, len(groups))
	for name := range groups {
		names = append(names, name)
	}
	sort.Strings(names)

	var targets []Target
	for _, name := range names {
		g := groups[name]
		for _, raw := range g.Hosts {
			t, err := parseEntry(name, g.Expect, g.StartTLS, raw)
			if err != nil {
				return nil, err
			}
			targets = append(targets, t)
		}
	}
	if len(targets) == 0 {
		return nil, fmt.Errorf("el inventario no contiene destinos")
	}
	return targets, nil
}

// parseEntry acepta tanto la forma corta (string) como la tabla inline.
func parseEntry(groupName, groupExpect, groupStartTLS string, raw any) (Target, error) {
	var addr, expect, startTLS string

	switch v := raw.(type) {
	case string:
		addr = v
	case map[string]any:
		for key, val := range v {
			s, ok := val.(string)
			if !ok {
				return Target{}, fmt.Errorf("grupo %q: la clave %q debe ser texto", groupName, key)
			}
			switch key {
			case "addr":
				addr = s
			case "expect":
				expect = s
			case "starttls":
				startTLS = s
			default:
				// Un typo silencioso aca dejaria el destino mal chequeado.
				return Target{}, fmt.Errorf("grupo %q: clave desconocida %q (validas: addr, expect, starttls)", groupName, key)
			}
		}
		if addr == "" {
			return Target{}, fmt.Errorf("grupo %q: entrada sin clave addr", groupName)
		}
	default:
		return Target{}, fmt.Errorf("grupo %q: entrada invalida %v: se espera \"host:puerto\" o { addr = ..., expect = ... }", groupName, raw)
	}

	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return Target{}, fmt.Errorf("grupo %q: entrada %q invalida: %w", groupName, addr, err)
	}
	if host == "" {
		return Target{}, fmt.Errorf("grupo %q: entrada %q sin host", groupName, addr)
	}
	if n, err := strconv.Atoi(port); err != nil || n < 1 || n > 65535 {
		return Target{}, fmt.Errorf("grupo %q: entrada %q con puerto invalido %q", groupName, addr, port)
	}

	if expect == "" {
		expect = groupExpect
	}
	if startTLS == "" {
		startTLS = groupStartTLS
	}
	startTLS, err = resolveStartTLS(groupName, addr, port, startTLS)
	if err != nil {
		return Target{}, err
	}

	return Target{
		Group:    groupName,
		Host:     host,
		Port:     port,
		Addr:     net.JoinHostPort(host, port),
		Expect:   expect,
		StartTLS: startTLS,
	}, nil
}

// resolveStartTLS valida el valor explicito y, si no hay ninguno, lo infiere
// del puerto. Devuelve cadena vacia para TLS implicito, de modo que el resto
// del codigo pregunta una sola cosa.
func resolveStartTLS(groupName, addr, port, value string) (string, error) {
	if value == "" {
		return startTLSByPort[port], nil
	}
	if !slices.Contains(startTLSValues, value) {
		// Un typo silencioso dejaria el destino mal chequeado.
		return "", fmt.Errorf("grupo %q: entrada %q con starttls %q invalido (validos: %v)",
			groupName, addr, value, startTLSValues)
	}
	if value == startTLSNone {
		return "", nil
	}
	return value, nil
}
