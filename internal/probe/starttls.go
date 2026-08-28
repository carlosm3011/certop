package probe

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"sync"

	"github.com/lacniclabs/certop/internal/inventory"
)

// errNoStartTLS marca que el servidor contesto bien pero no ofrece STARTTLS.
// Es un hallazgo sobre el servidor, no una falla del chequeo, y por eso se
// distingue de cualquier otro error.
var errNoStartTLS = errors.New("el servidor no ofrece STARTTLS")

// startTLS negocia TLS sobre una sesion en claro y deja la conexion lista para
// el handshake. El deadline de la conexion ya viene puesto por el llamador y
// cubre todo el preambulo.
func startTLS(conn net.Conn, proto string) error {
	br := bufio.NewReader(conn)

	var err error
	switch proto {
	case inventory.StartTLSSMTP:
		err = startTLSSMTP(conn, br)
	case inventory.StartTLSIMAP:
		err = startTLSIMAP(conn, br)
	case inventory.StartTLSPOP3:
		err = startTLSPOP3(conn, br)
	default:
		err = fmt.Errorf("protocolo starttls desconocido %q", proto)
	}
	if err != nil {
		return err
	}

	// El handshake lee de la conexion, no del bufio.Reader: si quedo algo
	// buferado, esos bytes se pierden y el handshake falla de forma confusa.
	// Mejor decirlo.
	if n := br.Buffered(); n != 0 {
		return fmt.Errorf("el servidor mando %d bytes de mas antes del handshake", n)
	}
	return nil
}

// readLine lee una linea y le saca el CRLF.
func readLine(br *bufio.Reader) (string, error) {
	line, err := br.ReadString('\n')
	if err != nil {
		if errors.Is(err, io.EOF) && line != "" {
			return strings.TrimRight(line, "\r\n"), nil
		}
		return "", err
	}
	return strings.TrimRight(line, "\r\n"), nil
}

func sendLine(conn net.Conn, format string, args ...any) error {
	_, err := fmt.Fprintf(conn, format+"\r\n", args...)
	return err
}

// ehloName es el nombre con el que nos presentamos; no tiene por que resolver.
var ehloName = sync.OnceValue(func() string {
	if name, err := os.Hostname(); err == nil && name != "" {
		return name
	}
	return "certop"
})

// smtpReply lee una respuesta de SMTP, que puede ser multilinea: las lineas
// intermedias traen un guion despues del codigo ("250-CAPACIDAD") y la ultima
// un espacio ("250 CAPACIDAD"). Hay que consumirla entera o la proxima lectura
// arranca desmontada.
func smtpReply(br *bufio.Reader) (code string, lines []string, err error) {
	for {
		line, err := readLine(br)
		if err != nil {
			return "", nil, err
		}
		if len(line) < 4 {
			// Una linea corta solo puede ser la ultima.
			lines = append(lines, line)
			if len(line) >= 3 {
				return line[:3], lines, nil
			}
			return "", lines, fmt.Errorf("respuesta smtp ilegible: %q", line)
		}
		code, sep, rest := line[:3], line[3], line[4:]
		lines = append(lines, rest)
		if sep == ' ' {
			return code, lines, nil
		}
		if sep != '-' {
			return "", nil, fmt.Errorf("respuesta smtp ilegible: %q", line)
		}
	}
}

func startTLSSMTP(conn net.Conn, br *bufio.Reader) error {
	code, _, err := smtpReply(br)
	if err != nil {
		return fmt.Errorf("saludo smtp: %w", err)
	}
	if code != "220" {
		return fmt.Errorf("saludo smtp inesperado: %s", code)
	}

	if err := sendLine(conn, "EHLO %s", ehloName()); err != nil {
		return err
	}
	code, lines, err := smtpReply(br)
	if err != nil {
		return fmt.Errorf("ehlo: %w", err)
	}
	if code != "250" {
		return fmt.Errorf("ehlo rechazado: %s", code)
	}

	// Solo se manda STARTTLS si el servidor lo anuncia.
	offered := false
	for _, line := range lines {
		fields := strings.Fields(line)
		if len(fields) > 0 && strings.EqualFold(fields[0], "STARTTLS") {
			offered = true
			break
		}
	}
	if !offered {
		return errNoStartTLS
	}

	if err := sendLine(conn, "STARTTLS"); err != nil {
		return err
	}
	code, _, err = smtpReply(br)
	if err != nil {
		return fmt.Errorf("starttls: %w", err)
	}
	if code != "220" {
		// Lo anuncia pero lo rechaza: para el operador es lo mismo que no
		// tenerlo.
		return fmt.Errorf("%w (respondio %s)", errNoStartTLS, code)
	}
	return nil
}

func startTLSIMAP(conn net.Conn, br *bufio.Reader) error {
	greeting, err := readLine(br)
	if err != nil {
		return fmt.Errorf("saludo imap: %w", err)
	}
	if !strings.HasPrefix(greeting, "* OK") {
		return fmt.Errorf("saludo imap inesperado: %q", firstWords(greeting))
	}

	if err := sendLine(conn, "a001 STARTTLS"); err != nil {
		return err
	}
	for {
		line, err := readLine(br)
		if err != nil {
			return fmt.Errorf("starttls: %w", err)
		}
		// Las lineas "*" son informativas; la respuesta es la etiquetada.
		if strings.HasPrefix(line, "* ") {
			continue
		}
		switch {
		case strings.HasPrefix(line, "a001 OK"):
			return nil
		case strings.HasPrefix(line, "a001 NO"), strings.HasPrefix(line, "a001 BAD"):
			return fmt.Errorf("%w (%s)", errNoStartTLS, firstWords(line))
		default:
			return fmt.Errorf("respuesta imap inesperada: %q", firstWords(line))
		}
	}
}

func startTLSPOP3(conn net.Conn, br *bufio.Reader) error {
	greeting, err := readLine(br)
	if err != nil {
		return fmt.Errorf("saludo pop3: %w", err)
	}
	if !strings.HasPrefix(greeting, "+OK") {
		return fmt.Errorf("saludo pop3 inesperado: %q", firstWords(greeting))
	}

	if err := sendLine(conn, "STLS"); err != nil {
		return err
	}
	line, err := readLine(br)
	if err != nil {
		return fmt.Errorf("stls: %w", err)
	}
	if !strings.HasPrefix(line, "+OK") {
		return fmt.Errorf("%w (%s)", errNoStartTLS, firstWords(line))
	}
	return nil
}

// firstWords recorta para que un servidor charlatan no llene la pantalla.
func firstWords(s string) string {
	const max = 60
	if len(s) > max {
		return s[:max] + "..."
	}
	return s
}
