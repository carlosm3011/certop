package inventory

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestParseValid(t *testing.T) {
	data := []byte(`
[email]
hosts = ["mail.lacnic.net:993", "mail.lacnic.net.uy:993", "mail.lacnic.net.uy:465"]

[frontends]
hosts = ["rpki-fe-1.lacnic.net:443"]
`)
	got, err := Parse(data)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	want := []Target{
		{"email", "mail.lacnic.net", "993", "mail.lacnic.net:993", ""},
		{"email", "mail.lacnic.net.uy", "993", "mail.lacnic.net.uy:993", ""},
		{"email", "mail.lacnic.net.uy", "465", "mail.lacnic.net.uy:465", ""},
		{"frontends", "rpki-fe-1.lacnic.net", "443", "rpki-fe-1.lacnic.net:443", ""},
	}
	if len(got) != len(want) {
		t.Fatalf("got %d targets, want %d: %+v", len(got), len(want), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("target %d = %+v, want %+v", i, got[i], want[i])
		}
	}
}

// Los grupos deben salir siempre en el mismo orden pese al mapa TOML.
func TestParseDeterministicOrder(t *testing.T) {
	data := []byte("[zeta]\nhosts=[\"z:1\"]\n[alpha]\nhosts=[\"a:1\"]\n[medio]\nhosts=[\"m:1\"]\n")
	for i := 0; i < 20; i++ {
		got, err := Parse(data)
		if err != nil {
			t.Fatal(err)
		}
		if got[0].Group != "alpha" || got[1].Group != "medio" || got[2].Group != "zeta" {
			t.Fatalf("orden no determinista en la corrida %d: %+v", i, got)
		}
	}
}

// El mismo host en dos puertos son dos destinos distintos.
func TestParseKeepsRepeatedHost(t *testing.T) {
	got, err := Parse([]byte(`[email]
hosts = ["mail.lacnic.net.uy:993", "mail.lacnic.net.uy:465"]`))
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("got %d targets, want 2", len(got))
	}
	if got[0].Port == got[1].Port {
		t.Errorf("los puertos deberian diferir: %+v", got)
	}
}

func TestParseIPv6(t *testing.T) {
	got, err := Parse([]byte(`[v6]
hosts = ["[2001:13c7:7002::1]:443"]`))
	if err != nil {
		t.Fatal(err)
	}
	if got[0].Host != "2001:13c7:7002::1" || got[0].Port != "443" {
		t.Errorf("got %+v", got[0])
	}
	if got[0].Addr != "[2001:13c7:7002::1]:443" {
		t.Errorf("Addr = %q", got[0].Addr)
	}
}

func TestParseErrors(t *testing.T) {
	cases := map[string]string{
		"toml malformado":       "[frontends\nhosts=[]",
		"sin puerto":            "[frontends]\nhosts=[\"host-sin-puerto\"]",
		"puerto no numero":      "[frontends]\nhosts=[\"host:https\"]",
		"puerto fuera de rango": "[frontends]\nhosts=[\"host:99999\"]",
		"sin host":              "[frontends]\nhosts=[\":443\"]",
		"grupo vacio":           "[frontends]\nhosts=[]",
		"sin grupos":            "",
	}
	for name, data := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := Parse([]byte(data)); err == nil {
				t.Errorf("se esperaba error para %q", data)
			}
		})
	}
}

func TestLoadMissingFile(t *testing.T) {
	if _, err := Load(filepath.Join(t.TempDir(), "no-existe.toml")); err == nil {
		t.Error("se esperaba error")
	}
}

func TestLoadExample(t *testing.T) {
	path := filepath.Join("..", "..", "hosts.toml.example")
	if _, err := os.Stat(path); err != nil {
		t.Skipf("no hay ejemplo: %v", err)
	}
	got, err := Load(path)
	if err != nil {
		t.Fatalf("el inventario de ejemplo no parsea: %v", err)
	}
	if len(got) != 8 {
		t.Errorf("got %d destinos, want 8", len(got))
	}
}

func TestParseExpect(t *testing.T) {
	data := []byte(`
[rpki-frontends]
expect = "rrdp.lacnic.net"
hosts = [
  "fe-1.rrdp.lacnic.net:443",
  { addr = "otro.lacnic.net:443", expect = "www.lacnic.net" },
  { addr = "sin-expect.lacnic.net:443" },
]

[email]
hosts = ["mail.lacnic.net.uy:993"]
`)
	got, err := Parse(data)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(got) != 4 {
		t.Fatalf("got %d destinos, want 4: %+v", len(got), got)
	}

	// email va primero por orden alfabetico y no tiene expect.
	if got[0].Expect != "" || got[0].VerifyName() != "mail.lacnic.net.uy" {
		t.Errorf("sin expect: %+v, VerifyName=%q", got[0], got[0].VerifyName())
	}
	// El expect del grupo aplica a la entrada corta.
	if got[1].Expect != "rrdp.lacnic.net" || got[1].VerifyName() != "rrdp.lacnic.net" {
		t.Errorf("expect de grupo: %+v", got[1])
	}
	// El expect de la entrada pisa al del grupo.
	if got[2].Expect != "www.lacnic.net" {
		t.Errorf("override por entrada: %+v", got[2])
	}
	// Tabla inline sin expect propio hereda el del grupo.
	if got[3].Expect != "rrdp.lacnic.net" {
		t.Errorf("tabla inline sin expect: %+v", got[3])
	}
}

func TestParseEntryErrors(t *testing.T) {
	cases := map[string]string{
		"clave desconocida": `[g]
hosts = [{ addr = "h:443", expct = "x" }]`,
		"sin addr": `[g]
hosts = [{ expect = "x" }]`,
		"addr no es texto": `[g]
hosts = [{ addr = 443 }]`,
		"entrada numerica": `[g]
hosts = [443]`,
	}
	for name, data := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := Parse([]byte(data)); err == nil {
				t.Errorf("se esperaba error para %q", data)
			}
		})
	}
}

// Un typo en la clave tiene que nombrarse en el error, no pasar en silencio.
func TestParseUnknownKeyMentionsIt(t *testing.T) {
	_, err := Parse([]byte("[g]\nhosts = [{ addr = 'h:443', expct = 'x' }]"))
	if err == nil {
		t.Fatal("se esperaba error")
	}
	if !strings.Contains(err.Error(), "expct") {
		t.Errorf("el error no menciona la clave: %v", err)
	}
}
