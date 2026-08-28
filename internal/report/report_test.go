package report

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/csv"
	"encoding/json"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/lacniclabs/certop/internal/inventory"
	"github.com/lacniclabs/certop/internal/probe"
)

var checkedAt = time.Date(2026, 8, 27, 12, 0, 0, 0, time.UTC)

func sample() []probe.Result {
	ok := probe.Result{
		Target:     inventory.Target{Group: "frontends", Host: "rpki-fe-1.lacnic.net", Port: "443", Addr: "rpki-fe-1.lacnic.net:443", Expect: "rrdp.lacnic.net"},
		IP:         net.ParseIP("172.233.162.16"),
		AF:         4,
		TCP:        probe.TCPOK,
		Leaf:       &x509.Certificate{},
		NotAfter:   checkedAt.Add(45 * 24 * time.Hour),
		DaysLeft:   45,
		Issuer:     "Let's Encrypt R11",
		CertStatus: probe.CertOK,
		NegVersion: tls.VersionTLS13,
		NegCipher:  tls.TLS_AES_256_GCM_SHA384,
		KeyType:    "ECDSA P-256",
		SigAlg:     x509.SHA256WithRSA.String(),
		Versions: map[uint16]probe.VerState{
			tls.VersionTLS10: probe.VerNo, tls.VersionTLS11: probe.VerNo,
			tls.VersionTLS12: probe.VerYes, tls.VersionTLS13: probe.VerYes,
		},
		CheckedAt: checkedAt,
	}
	down := probe.Result{
		Target:    inventory.Target{Group: "email", Host: "mail.lacnic.net.uy", Port: "465", Addr: "mail.lacnic.net.uy:465", StartTLS: "smtp"},
		IP:        net.ParseIP("2001:db8::1"),
		AF:        6,
		TCP:       probe.TCPRefused,
		CheckedAt: checkedAt,
	}
	return []probe.Result{ok, down}
}

func TestWriteCSV(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteCSV(&buf, sample()); err != nil {
		t.Fatal(err)
	}
	rows, err := csv.NewReader(&buf).ReadAll()
	if err != nil {
		t.Fatalf("CSV invalido: %v", err)
	}
	if len(rows) != 3 {
		t.Fatalf("got %d filas, want 3", len(rows))
	}
	if len(rows[0]) != len(csvHeader) {
		t.Errorf("encabezado con %d columnas, want %d", len(rows[0]), len(csvHeader))
	}
	col := func(row []string, name string) string {
		for i, h := range csvHeader {
			if h == name {
				return row[i]
			}
		}
		t.Fatalf("columna %q no esta en el encabezado", name)
		return ""
	}
	if col(rows[1], "grupo") != "frontends" || col(rows[1], "dias_restantes") != "45" || col(rows[1], "estado_cert") != "OK" {
		t.Errorf("fila ok = %v", rows[1])
	}
	if col(rows[1], "af") != "4" || col(rows[1], "ip") != "172.233.162.16" {
		t.Errorf("af/ip = %q/%q", col(rows[1], "af"), col(rows[1], "ip"))
	}
	if col(rows[2], "af") != "6" || col(rows[2], "ip") != "2001:db8::1" {
		t.Errorf("af/ip v6 = %q/%q", col(rows[2], "af"), col(rows[2], "ip"))
	}
	if col(rows[1], "tls10") != "no" || col(rows[1], "tls13") != "si" {
		t.Errorf("matriz de versiones = %v", rows[1])
	}
	// Un destino caido deja los campos de certificado vacios, no en cero.
	if col(rows[2], "expira_utc") != "" || col(rows[2], "dias_restantes") != "" {
		t.Errorf("destino caido deberia tener expiracion vacia: %v", rows[2])
	}
	if col(rows[2], "tcp") != "rechazado" {
		t.Errorf("tcp = %q", col(rows[2], "tcp"))
	}
	// starttls va al final de la fila y queda vacio en TLS implicito.
	if csvHeader[len(csvHeader)-1] != "starttls" {
		t.Errorf("starttls deberia ser la ultima columna: %v", csvHeader)
	}
	if col(rows[1], "starttls") != "" || col(rows[2], "starttls") != "smtp" {
		t.Errorf("starttls = %q / %q", col(rows[1], "starttls"), col(rows[2], "starttls"))
	}
}

func TestWriteTable(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteTable(&buf, sample()); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	for _, want := range []string{"GRUPO", "AF", "IP", "rpki-fe-1.lacnic.net", "172.233.162.16", "2001:db8::1", "--23", "45d", "Let's Encrypt R11", "rechazado", Legend} {
		if !strings.Contains(out, want) {
			t.Errorf("falta %q en:\n%s", want, out)
		}
	}
}

func TestWriteJSON(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteJSON(&buf, sample()); err != nil {
		t.Fatal(err)
	}
	var got []map[string]any
	if err := json.Unmarshal(buf.Bytes(), &got); err != nil {
		t.Fatalf("JSON invalido: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("got %d elementos", len(got))
	}
	tlsMap, ok := got[0]["tls"].(map[string]any)
	if !ok {
		t.Fatalf("tls no es un objeto: %T", got[0]["tls"])
	}
	if tlsMap["1.3"] != true || tlsMap["1.0"] != false {
		t.Errorf("matriz = %v", tlsMap)
	}
	if got[0]["af"] != float64(4) || got[0]["ip"] != "172.233.162.16" {
		t.Errorf("af/ip = %v/%v", got[0]["af"], got[0]["ip"])
	}
	if got[0]["expect"] != "rrdp.lacnic.net" {
		t.Errorf("expect = %v", got[0]["expect"])
	}
	if got[1]["starttls"] != "smtp" {
		t.Errorf("starttls json = %v", got[1]["starttls"])
	}
	if _, ok := got[0]["starttls"]; ok {
		t.Errorf("starttls no deberia aparecer en TLS implicito: %v", got[0]["starttls"])
	}
	// Sin expect la clave se omite.
	if _, ok := got[1]["expect"]; ok {
		t.Errorf("expect no deberia aparecer: %v", got[1]["expect"])
	}
	if got[0]["dias_restantes"] != float64(45) {
		t.Errorf("dias_restantes = %v", got[0]["dias_restantes"])
	}
	// Sin certificado los campos van en null, no en 0.
	if got[1]["dias_restantes"] != nil || got[1]["expira_utc"] != nil {
		t.Errorf("destino caido = %v", got[1])
	}
	if tlsMap2 := got[1]["tls"].(map[string]any); tlsMap2["1.2"] != nil {
		t.Errorf("versiones sin sondear deberian ser null: %v", tlsMap2)
	}
}

func TestWriteUnknownFormat(t *testing.T) {
	if err := Write(&bytes.Buffer{}, sample(), "yaml"); err == nil {
		t.Error("se esperaba error")
	}
}

func TestExitCode(t *testing.T) {
	healthy := sample()[:1]
	all := sample()

	cases := []struct {
		name     string
		results  []probe.Result
		warnDays int
		want     int
	}{
		{"desactivado", all, -1, ExitOK},
		{"sano bajo umbral", healthy, 30, ExitOK},
		{"expira antes del umbral", healthy, 60, ExitWarn},
		{"destino inalcanzable", all, 1, ExitWarn},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := ExitCode(tc.results, tc.warnDays); got != tc.want {
				t.Errorf("ExitCode = %d, want %d", got, tc.want)
			}
		})
	}
}
