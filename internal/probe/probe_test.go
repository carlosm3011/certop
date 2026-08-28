package probe

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/carlosm3011/certop/internal/inventory"
)

// mint emite un certificado. Si parent es nil el certificado es autofirmado.
func mint(t *testing.T, cn string, dnsNames []string, notBefore, notAfter time.Time, isCA bool,
	parent *x509.Certificate, parentKey *ecdsa.PrivateKey) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	keyUsage := x509.KeyUsageDigitalSignature
	if isCA {
		keyUsage |= x509.KeyUsageCertSign
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              keyUsage,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  isCA,
		DNSNames:              dnsNames,
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
	}
	signer, signerKey := tmpl, key
	if parent != nil {
		signer, signerKey = parent, parentKey
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, signer, &key.PublicKey, signerKey)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert, key
}

func TestClassifyCert(t *testing.T) {
	now := time.Now()
	ca, caKey := mint(t, "CA de prueba", nil, now.Add(-24*time.Hour), now.Add(24*time.Hour), true, nil, nil)

	expired, _ := mint(t, "vencido", []string{"host.test"}, now.Add(-48*time.Hour), now.Add(-time.Hour), false, ca, caKey)
	selfSigned, _ := mint(t, "autofirmado", []string{"host.test"}, now.Add(-time.Hour), now.Add(24*time.Hour), false, nil, nil)
	wrongName, _ := mint(t, "otro", []string{"otro.test"}, now.Add(-time.Hour), now.Add(24*time.Hour), false, ca, caKey)
	orphan, _ := mint(t, "sin cadena", []string{"host.test"}, now.Add(-time.Hour), now.Add(24*time.Hour), false, ca, caKey)
	notYet, _ := mint(t, "futuro", []string{"host.test"}, now.Add(time.Hour), now.Add(24*time.Hour), false, ca, caKey)

	cases := []struct {
		name string
		leaf *x509.Certificate
		host string
		want CertStatus
	}{
		// La expiracion gana sobre el fallo de cadena que tambien produce.
		{"vencido", expired, "host.test", CertExpired},
		{"aun no valido", notYet, "host.test", CertExpired},
		{"autofirmado", selfSigned, "host.test", CertSelfSigned},
		{"nombre no coincide", wrongName, "host.test", CertHostnameMismatch},
		// Firmado por una CA que no esta en las raices del sistema.
		{"cadena incompleta", orphan, "host.test", CertIncompleteChain},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := classifyCert(tc.leaf, []*x509.Certificate{tc.leaf}, tc.host, now)
			if got != tc.want {
				t.Errorf("classifyCert = %v, want %v", got, tc.want)
			}
		})
	}
}

// serve levanta un servidor TLS local con los limites de version dados.
func serve(t *testing.T, min, max uint16) string {
	t.Helper()
	now := time.Now()
	cert, key := mint(t, "localhost", []string{"localhost"}, now.Add(-time.Hour), now.Add(90*24*time.Hour), false, nil, nil)
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{{Certificate: [][]byte{cert.Raw}, PrivateKey: key}},
		MinVersion:   min,
		MaxVersion:   max,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				if tc, ok := conn.(*tls.Conn); ok {
					_ = tc.HandshakeContext(context.Background())
				}
			}()
		}
	}()
	return ln.Addr().String()
}

func target(t *testing.T, addr string) inventory.Target {
	t.Helper()
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatal(err)
	}
	return inventory.Target{Group: "test", Host: host, Port: port, Addr: addr}
}

func TestCheckLiveServer(t *testing.T) {
	addr := serve(t, tls.VersionTLS12, tls.VersionTLS13)
	c := New(3*time.Second, 4, false)
	got := c.Check(context.Background(), target(t, addr))

	if got.TCP != TCPOK {
		t.Fatalf("TCP = %v, err = %v", got.TCP, got.Err)
	}
	if !got.HasCert() {
		t.Fatal("no se obtuvo el certificado")
	}
	// El certificado es autofirmado, pero igual debe reportar datos.
	if got.CertStatus != CertSelfSigned {
		t.Errorf("CertStatus = %v, want SELF-SIGNED", got.CertStatus)
	}
	if got.Issuer != "localhost" {
		t.Errorf("Issuer = %q", got.Issuer)
	}
	if got.KeyType != "ECDSA P-256" {
		t.Errorf("KeyType = %q", got.KeyType)
	}
	if got.DaysLeft < 88 || got.DaysLeft > 90 {
		t.Errorf("DaysLeft = %d, want ~89", got.DaysLeft)
	}
	// El servidor exige 1.2 como minimo.
	if got.Versions[tls.VersionTLS10] != VerNo || got.Versions[tls.VersionTLS11] != VerNo {
		t.Errorf("1.0/1.1 deberian rechazarse: %v", got.Versions)
	}
	if got.Versions[tls.VersionTLS12] != VerYes || got.Versions[tls.VersionTLS13] != VerYes {
		t.Errorf("1.2/1.3 deberian aceptarse: %v", got.Versions)
	}
	if want := "--23"; got.TLSDigits() != want {
		t.Errorf("TLSDigits = %q, want %q", got.TLSDigits(), want)
	}
}

// Verifica que el cliente realmente puede negociar TLS 1.0/1.1: la lista de
// cipher suites por defecto de Go las dejaria fuera y el sondeo reportaria
// falsos negativos.
func TestProbeNegotiatesLegacyVersions(t *testing.T) {
	addr := serve(t, tls.VersionTLS10, tls.VersionTLS11)
	c := New(3*time.Second, 4, false)
	got := c.Check(context.Background(), target(t, addr))

	if got.TCP != TCPOK {
		t.Fatalf("TCP = %v, err = %v", got.TCP, got.Err)
	}
	if got.Versions[tls.VersionTLS10] != VerYes {
		t.Errorf("TLS 1.0 = %v, want si", got.Versions[tls.VersionTLS10])
	}
	if got.Versions[tls.VersionTLS11] != VerYes {
		t.Errorf("TLS 1.1 = %v, want si", got.Versions[tls.VersionTLS11])
	}
	if got.Versions[tls.VersionTLS12] != VerNo || got.Versions[tls.VersionTLS13] != VerNo {
		t.Errorf("1.2/1.3 deberian rechazarse: %v", got.Versions)
	}
	if want := "01--"; got.TLSDigits() != want {
		t.Errorf("TLSDigits = %q, want %q", got.TLSDigits(), want)
	}
}

// La matriz se sondea una sola vez salvo que se pida lo contrario.
func TestVersionMatrixCached(t *testing.T) {
	addr := serve(t, tls.VersionTLS12, tls.VersionTLS13)
	tgt := target(t, addr)
	c := New(3*time.Second, 4, false)

	first := c.Check(context.Background(), tgt)
	second := c.Check(context.Background(), tgt)
	if !second.ProbedAt.Equal(first.ProbedAt) {
		t.Errorf("la segunda pasada resondeo: %v vs %v", second.ProbedAt, first.ProbedAt)
	}

	c.InvalidateVersions()
	third := c.Check(context.Background(), tgt)
	if third.ProbedAt.Equal(first.ProbedAt) {
		t.Error("InvalidateVersions no forzo el re-sondeo")
	}

	always := New(3*time.Second, 4, true)
	a1 := always.Check(context.Background(), tgt)
	a2 := always.Check(context.Background(), tgt)
	if a1.ProbedAt.Equal(a2.ProbedAt) {
		t.Error("--probe-always deberia resondear en cada pasada")
	}
}

func TestCheckRefused(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	ln.Close() // nadie escucha en ese puerto

	c := New(2*time.Second, 4, false)
	got := c.Check(context.Background(), target(t, addr))
	if got.TCP != TCPRefused {
		t.Errorf("TCP = %v, want rechazado (err = %v)", got.TCP, got.Err)
	}
	if got.HasCert() {
		t.Error("no deberia haber certificado")
	}
	if got.TLSDigits() != "????" {
		t.Errorf("TLSDigits = %q, want ????", got.TLSDigits())
	}
}

func TestCheckDNSFailure(t *testing.T) {
	c := New(3*time.Second, 4, false)
	tgt := inventory.Target{Group: "g", Host: "no.existe.invalid", Port: "443", Addr: "no.existe.invalid:443"}
	got := c.Check(context.Background(), tgt)
	if got.TCP != TCPDNS {
		t.Errorf("TCP = %v, want dns (err = %v)", got.TCP, got.Err)
	}
}

func TestRunPreservesOrder(t *testing.T) {
	addr := serve(t, tls.VersionTLS12, tls.VersionTLS13)
	targets := make([]inventory.Target, 6)
	for i := range targets {
		targets[i] = target(t, addr)
		targets[i].Group = string(rune('a' + i))
	}
	c := New(3*time.Second, 3, false)

	var mu sync.Mutex
	notified := 0
	got := c.Run(context.Background(), targets, func(Result) {
		mu.Lock()
		notified++
		mu.Unlock()
	})
	if len(got) != len(targets) {
		t.Fatalf("got %d resultados, want %d", len(got), len(targets))
	}
	for i := range targets {
		if got[i].Group != targets[i].Group {
			t.Errorf("resultado %d fuera de orden: %q", i, got[i].Group)
		}
	}
	if notified != len(targets) {
		t.Errorf("se notificaron %d resultados, want %d", notified, len(targets))
	}
}

func TestVersionVerdict(t *testing.T) {
	if got := versionVerdict(nil); got != VerYes {
		t.Errorf("nil = %v", got)
	}
	if got := versionVerdict(context.DeadlineExceeded); got != VerUnknown {
		t.Errorf("deadline = %v, want ?", got)
	}
	if got := versionVerdict(errors.New("remote error: tls: protocol version not supported")); got != VerNo {
		t.Errorf("alerta tls = %v, want no", got)
	}
}

func TestDaysLeft(t *testing.T) {
	now := time.Date(2026, 8, 27, 12, 0, 0, 0, time.UTC)
	cases := []struct {
		notAfter time.Time
		want     int
	}{
		{now.Add(48 * time.Hour), 2},
		{now.Add(47 * time.Hour), 1},
		{now.Add(-time.Hour), -1},
		{now.Add(-48 * time.Hour), -2},
	}
	for _, tc := range cases {
		if got := daysLeft(tc.notAfter, now); got != tc.want {
			t.Errorf("daysLeft(%v) = %d, want %d", tc.notAfter, got, tc.want)
		}
	}
}

// serveAny levanta un servidor TLS en todas las interfaces, de modo que
// localhost lo alcance tanto por IPv4 como por IPv6 en el mismo puerto.
func serveAny(t *testing.T, cn string, dnsNames []string) string {
	t.Helper()
	now := time.Now()
	cert, key := mint(t, cn, dnsNames, now.Add(-time.Hour), now.Add(90*24*time.Hour), false, nil, nil)
	ln, err := tls.Listen("tcp", ":0", &tls.Config{
		Certificates: []tls.Certificate{{Certificate: [][]byte{cert.Raw}, PrivateKey: key}},
		MinVersion:   tls.VersionTLS12,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				if tc, ok := conn.(*tls.Conn); ok {
					_ = tc.HandshakeContext(context.Background())
				}
			}()
		}
	}()
	_, port, _ := net.SplitHostPort(ln.Addr().String())
	return port
}

// Un nombre dual-stack produce una fila por familia: es el caso de "actualizaron
// el config de A y se olvidaron del AAAA".
func TestRunFanOutPerAddressFamily(t *testing.T) {
	port := serveAny(t, "localhost", []string{"localhost"})
	tgt := inventory.Target{Group: "g", Host: "localhost", Port: port, Addr: "localhost:" + port}

	c := New(3*time.Second, 4, false)
	got := c.Run(context.Background(), []inventory.Target{tgt}, nil)

	if len(got) != 2 {
		t.Fatalf("got %d filas, want 2 (una por familia): %+v", len(got), got)
	}
	// v4 antes que v6, orden estable.
	if got[0].AF != 4 || got[1].AF != 6 {
		t.Errorf("familias = %d, %d; want 4, 6", got[0].AF, got[1].AF)
	}
	if got[0].AFText() != "4" || got[1].AFText() != "6" {
		t.Errorf("AFText = %q, %q", got[0].AFText(), got[1].AFText())
	}
	if !got[0].IP.Equal(net.ParseIP("127.0.0.1")) {
		t.Errorf("IP v4 = %v", got[0].IP)
	}
	if !got[1].IP.Equal(net.ParseIP("::1")) {
		t.Errorf("IP v6 = %v", got[1].IP)
	}
	for i, r := range got {
		if r.TCP != TCPOK || !r.HasCert() {
			t.Errorf("fila %d: TCP=%v err=%v", i, r.TCP, r.Err)
		}
	}
	// Las dos filas son el mismo servidor: misma expiracion.
	if got[0].DaysLeft != got[1].DaysLeft {
		t.Errorf("expiraciones distintas: %d vs %d", got[0].DaysLeft, got[1].DaysLeft)
	}
	// Claves distintas: la fila ya no se identifica por el destino.
	if got[0].Key() == got[1].Key() {
		t.Error("las dos familias comparten Key()")
	}
}

// El orden de las direcciones tiene que ser estable entre pasadas, aunque el
// resolver las devuelva rotadas.
func TestRunAddressOrderStable(t *testing.T) {
	port := serveAny(t, "localhost", []string{"localhost"})
	tgt := inventory.Target{Group: "g", Host: "localhost", Port: port, Addr: "localhost:" + port}
	c := New(3*time.Second, 4, false)

	var first []string
	for pass := 0; pass < 5; pass++ {
		var keys []string
		for _, r := range c.Run(context.Background(), []inventory.Target{tgt}, nil) {
			keys = append(keys, r.IPText())
		}
		if pass == 0 {
			first = keys
			continue
		}
		if len(keys) != len(first) {
			t.Fatalf("pasada %d: %d filas, want %d", pass, len(keys), len(first))
		}
		for i := range keys {
			if keys[i] != first[i] {
				t.Errorf("pasada %d: orden cambio en %d: %q vs %q", pass, i, keys[i], first[i])
			}
		}
	}
}

// expect fija el SNI y el nombre contra el que se valida: es el caso de los
// nodos detras del CNAME, cuyo certificado nunca lleva su propio nombre.
func TestExpectDrivesVerification(t *testing.T) {
	port := serveAny(t, "esperado.test", []string{"esperado.test"})

	sinExpect := inventory.Target{Group: "g", Host: "localhost", Port: port, Addr: "localhost:" + port}
	conExpect := sinExpect
	conExpect.Expect = "esperado.test"

	c := New(3*time.Second, 4, false)

	got := c.Check(context.Background(), sinExpect)
	if got.CertStatus != CertHostnameMismatch {
		t.Errorf("sin expect: %v, want NOMBRE-NO-COINCIDE (err=%v)", got.CertStatus, got.Err)
	}

	// Con expect el nombre valida; la cadena sigue sin ser confiable porque el
	// certificado es autofirmado.
	got = c.Check(context.Background(), conExpect)
	if got.CertStatus != CertSelfSigned {
		t.Errorf("con expect: %v, want SELF-SIGNED (err=%v)", got.CertStatus, got.Err)
	}
	if got.VerifyName() != "esperado.test" {
		t.Errorf("VerifyName = %q", got.VerifyName())
	}
}

// Una entrada cuyo nombre no resuelve tiene que dejar una fila visible.
func TestExpandKeepsDNSFailureRow(t *testing.T) {
	c := New(2*time.Second, 4, false)
	tgt := inventory.Target{Group: "g", Host: "no.existe.invalid", Port: "443", Addr: "no.existe.invalid:443"}

	got := c.Run(context.Background(), []inventory.Target{tgt}, nil)
	if len(got) != 1 {
		t.Fatalf("got %d filas, want 1", len(got))
	}
	if got[0].TCP != TCPDNS {
		t.Errorf("TCP = %v, want dns", got[0].TCP)
	}
	if got[0].AFText() != "-" || got[0].IPText() != "-" {
		t.Errorf("AF/IP = %q/%q, want -/-", got[0].AFText(), got[0].IPText())
	}
}

// Un literal IP no se resuelve: una sola fila, la familia de esa direccion.
func TestRunIPLiteral(t *testing.T) {
	addr := serve(t, tls.VersionTLS12, tls.VersionTLS13)
	tgt := target(t, addr)

	got := New(3*time.Second, 4, false).Run(context.Background(), []inventory.Target{tgt}, nil)
	if len(got) != 1 {
		t.Fatalf("got %d filas, want 1", len(got))
	}
	if got[0].AF != 4 {
		t.Errorf("AF = %d, want 4", got[0].AF)
	}
}
