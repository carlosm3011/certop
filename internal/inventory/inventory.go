// Package inventory lee el archivo TOML de inventario y lo aplana en una lista
// de destinos a chequear.
package inventory

import (
	"fmt"
	"net"
	"os"
	"sort"
	"strconv"

	"github.com/pelletier/go-toml/v2"
)

// Target es un destino individual: un host y un puerto dentro de un grupo.
type Target struct {
	Group string
	Host  string
	Port  string
	// Addr es "host:puerto", la forma que consume net.Dial directamente.
	Addr string
}

type group struct {
	Hosts []string `toml:"hosts"`
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
		for _, entry := range groups[name].Hosts {
			host, port, err := net.SplitHostPort(entry)
			if err != nil {
				return nil, fmt.Errorf("grupo %q: entrada %q invalida: %w", name, entry, err)
			}
			if host == "" {
				return nil, fmt.Errorf("grupo %q: entrada %q sin host", name, entry)
			}
			if n, err := strconv.Atoi(port); err != nil || n < 1 || n > 65535 {
				return nil, fmt.Errorf("grupo %q: entrada %q con puerto invalido %q", name, entry, port)
			}
			targets = append(targets, Target{
				Group: name,
				Host:  host,
				Port:  port,
				Addr:  net.JoinHostPort(host, port),
			})
		}
	}
	if len(targets) == 0 {
		return nil, fmt.Errorf("el inventario no contiene destinos")
	}
	return targets, nil
}
