package probe

import (
	"bufio"
	"context"
	"crypto/tls"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/lacniclabs/certop/internal/inventory"
)

// scriptedServer levanta un servidor que habla el preambulo con speak y, si
// speak devuelve true, envuelve la conexion con TLS. Deja probar los tres
// protocolos sin salir del proceso.
func scriptedServer(t *testing.T, speak func(conn net.Conn, br *bufio.Reader) bool) string {
	t.Helper()
	now := time.Now()
	cert, key := mint(t, "localhost", []string{"localhost"}, now.Add(-time.Hour), now.Add(90*24*time.Hour), false, nil, nil)
	cfg := &tls.Config{
		Certificates: []tls.Certificate{{Certificate: [][]byte{cert.Raw}, PrivateKey: key}},
		MinVersion:   tls.VersionTLS12,
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
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
				_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
				if !speak(conn, bufio.NewReader(conn)) {
					return
				}
				tc := tls.Server(conn, cfg)
				_ = tc.HandshakeContext(context.Background())
			}()
		}
	}()
	return ln.Addr().String()
}

func line(conn net.Conn, s string) { _, _ = conn.Write([]byte(s + "\r\n")) }

// smtpScript responde el saludo y el EHLO con las capacidades dadas.
func smtpScript(greeting []string, caps []string, acceptStartTLS bool) func(net.Conn, *bufio.Reader) bool {
	return func(conn net.Conn, br *bufio.Reader) bool {
		for i, g := range greeting {
			sep := "-"
			if i == len(greeting)-1 {
				sep = " "
			}
			line(conn, "220"+sep+g)
		}
		if _, err := br.ReadString('\n'); err != nil { // EHLO
			return false
		}
		for i, c := range caps {
			sep := "-"
			if i == len(caps)-1 {
				sep = " "
			}
			line(conn, "250"+sep+c)
		}
		cmd, err := br.ReadString('\n')
		if err != nil || !strings.HasPrefix(strings.ToUpper(cmd), "STARTTLS") {
			return false
		}
		if !acceptStartTLS {
			line(conn, "454 TLS no disponible")
			return false
		}
		line(conn, "220 adelante")
		return true
	}
}

func targetFor(t *testing.T, addr, proto string) inventory.Target {
	t.Helper()
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatal(err)
	}
	return inventory.Target{Group: "g", Host: host, Port: port, Addr: addr, StartTLS: proto}
}

func TestStartTLSSMTP(t *testing.T) {
	// Saludo multilinea y un bloque de capacidades largo, como responde un
	// Postfix real.
	addr := scriptedServer(t, smtpScript(
		[]string{"mail.example ESMTP Postfix", "listo"},
		[]string{"mail.example", "PIPELINING", "SIZE 50240000", "STARTTLS", "8BITMIME"},
		true))

	got := New(3*time.Second, 4, false).Check(context.Background(), targetFor(t, addr, "smtp"))
	if got.TCP != TCPOK || !got.HasCert() {
		t.Fatalf("TCP=%v cert=%v err=%v", got.TCP, got.HasCert(), got.Err)
	}
	if got.CertStatus != CertSelfSigned {
		t.Errorf("CertStatus = %v, want SELF-SIGNED", got.CertStatus)
	}
	if got.Issuer != "localhost" {
		t.Errorf("Issuer = %q", got.Issuer)
	}
}

// Si el EHLO no anuncia STARTTLS, es un hallazgo sobre el servidor.
func TestStartTLSSMTPNotOffered(t *testing.T) {
	addr := scriptedServer(t, smtpScript(
		[]string{"mail.example ESMTP"},
		[]string{"mail.example", "PIPELINING", "8BITMIME"},
		true))

	got := New(3*time.Second, 4, false).Check(context.Background(), targetFor(t, addr, "smtp"))
	if got.CertStatus != CertNoStartTLS {
		t.Errorf("CertStatus = %v, want SIN-STARTTLS (err=%v)", got.CertStatus, got.Err)
	}
	if got.TCP != TCPOK {
		t.Errorf("el socket estaba bien: TCP = %v", got.TCP)
	}
	if got.Severity(30) != SevProblem {
		t.Errorf("severidad = %v, want problema", got.Severity(30))
	}
}

// Lo anuncia y despues lo rechaza: para el operador es lo mismo.
func TestStartTLSSMTPAdvertisedButRefused(t *testing.T) {
	addr := scriptedServer(t, smtpScript(
		[]string{"mail.example ESMTP"},
		[]string{"mail.example", "STARTTLS"},
		false))

	got := New(3*time.Second, 4, false).Check(context.Background(), targetFor(t, addr, "smtp"))
	if got.CertStatus != CertNoStartTLS {
		t.Errorf("CertStatus = %v, want SIN-STARTTLS (err=%v)", got.CertStatus, got.Err)
	}
}

func TestStartTLSIMAP(t *testing.T) {
	addr := scriptedServer(t, func(conn net.Conn, br *bufio.Reader) bool {
		line(conn, "* OK [CAPABILITY IMAP4rev1 STARTTLS] servidor listo")
		if _, err := br.ReadString('\n'); err != nil {
			return false
		}
		line(conn, "* algo informativo")
		line(conn, "a001 OK adelante")
		return true
	})

	got := New(3*time.Second, 4, false).Check(context.Background(), targetFor(t, addr, "imap"))
	if got.TCP != TCPOK || !got.HasCert() {
		t.Fatalf("TCP=%v cert=%v err=%v", got.TCP, got.HasCert(), got.Err)
	}
}

func TestStartTLSIMAPRefused(t *testing.T) {
	addr := scriptedServer(t, func(conn net.Conn, br *bufio.Reader) bool {
		line(conn, "* OK servidor listo")
		if _, err := br.ReadString('\n'); err != nil {
			return false
		}
		line(conn, "a001 BAD no soportado")
		return false
	})

	got := New(3*time.Second, 4, false).Check(context.Background(), targetFor(t, addr, "imap"))
	if got.CertStatus != CertNoStartTLS {
		t.Errorf("CertStatus = %v, want SIN-STARTTLS (err=%v)", got.CertStatus, got.Err)
	}
}

func TestStartTLSPOP3(t *testing.T) {
	addr := scriptedServer(t, func(conn net.Conn, br *bufio.Reader) bool {
		line(conn, "+OK servidor pop3 listo")
		if _, err := br.ReadString('\n'); err != nil {
			return false
		}
		line(conn, "+OK adelante")
		return true
	})

	got := New(3*time.Second, 4, false).Check(context.Background(), targetFor(t, addr, "pop3"))
	if got.TCP != TCPOK || !got.HasCert() {
		t.Fatalf("TCP=%v cert=%v err=%v", got.TCP, got.HasCert(), got.Err)
	}
}

func TestStartTLSPOP3Refused(t *testing.T) {
	addr := scriptedServer(t, func(conn net.Conn, br *bufio.Reader) bool {
		line(conn, "+OK servidor pop3 listo")
		if _, err := br.ReadString('\n'); err != nil {
			return false
		}
		line(conn, "-ERR no")
		return false
	})

	got := New(3*time.Second, 4, false).Check(context.Background(), targetFor(t, addr, "pop3"))
	if got.CertStatus != CertNoStartTLS {
		t.Errorf("CertStatus = %v, want SIN-STARTTLS (err=%v)", got.CertStatus, got.Err)
	}
}

// La matriz de versiones tambien arrastra el preambulo.
func TestStartTLSVersionMatrix(t *testing.T) {
	addr := scriptedServer(t, smtpScript(
		[]string{"mail.example ESMTP"},
		[]string{"mail.example", "STARTTLS"},
		true))

	got := New(3*time.Second, 4, false).Check(context.Background(), targetFor(t, addr, "smtp"))
	if got.Versions[tls.VersionTLS12] != VerYes || got.Versions[tls.VersionTLS13] != VerYes {
		t.Errorf("1.2/1.3 deberian aceptarse sobre starttls: %v", got.Versions)
	}
	if got.Versions[tls.VersionTLS10] != VerNo {
		t.Errorf("1.0 = %v, want no", got.Versions[tls.VersionTLS10])
	}
	if want := "--23"; got.TLSDigits() != want {
		t.Errorf("TLSDigits = %q, want %q", got.TLSDigits(), want)
	}
}

// Un puerto en claro que no habla el protocolo esperado no puede quedar como
// SIN-STARTTLS: es un error del chequeo.
func TestStartTLSWrongProtocol(t *testing.T) {
	addr := scriptedServer(t, func(conn net.Conn, br *bufio.Reader) bool {
		line(conn, "HTTP/1.0 200 OK")
		return false
	})

	got := New(2*time.Second, 4, false).Check(context.Background(), targetFor(t, addr, "smtp"))
	if got.CertStatus != CertError {
		t.Errorf("CertStatus = %v, want ERROR (err=%v)", got.CertStatus, got.Err)
	}
}

// La matriz de versiones cuesta ~5 sesiones SMTP; la cache tiene que dejar los
// refrescos posteriores en una sola, para no golpear un servidor de correo en
// cada ciclo.
func TestStartTLSConnectionCost(t *testing.T) {
	var mu sync.Mutex
	conns := 0
	count := func(conn net.Conn, br *bufio.Reader) bool {
		mu.Lock()
		conns++
		mu.Unlock()
		return smtpScript(
			[]string{"mail.example ESMTP"},
			[]string{"mail.example", "STARTTLS"},
			true)(conn, br)
	}
	addr := scriptedServer(t, count)
	tgt := targetFor(t, addr, "smtp")
	c := New(3*time.Second, 4, false)

	c.Check(context.Background(), tgt)
	mu.Lock()
	first := conns
	mu.Unlock()
	if first < 4 || first > 6 {
		t.Errorf("primera pasada: %d conexiones, se esperaban ~5 (cert + 4 versiones)", first)
	}

	c.Check(context.Background(), tgt)
	mu.Lock()
	second := conns - first
	mu.Unlock()
	if second != 1 {
		t.Errorf("segunda pasada: %d conexiones, want 1 (la matriz sale de la cache)", second)
	}
}
