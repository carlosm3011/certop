package probe

import "crypto/tls"

// TCPState es el resultado del intento de conexion TCP.
type TCPState int

const (
	TCPUnknown TCPState = iota
	TCPOK
	TCPRefused
	TCPTimeout
	TCPDNS
	TCPError
)

func (s TCPState) String() string {
	switch s {
	case TCPOK:
		return "ok"
	case TCPRefused:
		return "rechazado"
	case TCPTimeout:
		return "timeout"
	case TCPDNS:
		return "dns"
	case TCPError:
		return "error"
	default:
		return "?"
	}
}

// OK indica si el socket TCP se establecio.
func (s TCPState) OK() bool { return s == TCPOK }

// CertStatus es el veredicto de validacion del certificado. El handshake se
// hace sin verificar, de modo que el certificado hoja se obtiene siempre y la
// validacion se reporta aparte.
type CertStatus int

const (
	CertUnknown CertStatus = iota
	CertOK
	CertExpired
	CertSelfSigned
	CertHostnameMismatch
	CertIncompleteChain
	CertError
)

func (s CertStatus) String() string {
	switch s {
	case CertOK:
		return "OK"
	case CertExpired:
		return "EXPIRADO"
	case CertSelfSigned:
		return "SELF-SIGNED"
	case CertHostnameMismatch:
		return "NOMBRE-NO-COINCIDE"
	case CertIncompleteChain:
		return "CADENA-INCOMPLETA"
	case CertError:
		return "ERROR"
	default:
		return "?"
	}
}

// OK indica si el certificado valido correctamente.
func (s CertStatus) OK() bool { return s == CertOK }

// VerState es el resultado de sondear una version de TLS concreta.
type VerState int

const (
	// VerUnknown: el sondeo no llego a completarse (fallo de red), que no es
	// lo mismo que el servidor rechazando la version.
	VerUnknown VerState = iota
	VerYes
	VerNo
)

func (s VerState) String() string {
	switch s {
	case VerYes:
		return "si"
	case VerNo:
		return "no"
	default:
		return "?"
	}
}

// Versions son las versiones de TLS que se sondean, en orden.
var Versions = []uint16{
	tls.VersionTLS10,
	tls.VersionTLS11,
	tls.VersionTLS12,
	tls.VersionTLS13,
}

// VersionName devuelve el nombre corto de una version ("1.2").
func VersionName(v uint16) string {
	switch v {
	case tls.VersionTLS10:
		return "1.0"
	case tls.VersionTLS11:
		return "1.1"
	case tls.VersionTLS12:
		return "1.2"
	case tls.VersionTLS13:
		return "1.3"
	default:
		return "?"
	}
}

// versionDigit es el caracter que representa a la version en la columna
// compacta de la pantalla: el digito si la acepta, "-" si la rechaza, "?" si no
// se pudo determinar.
func versionDigit(v uint16, s VerState) rune {
	switch s {
	case VerYes:
		switch v {
		case tls.VersionTLS10:
			return '0'
		case tls.VersionTLS11:
			return '1'
		case tls.VersionTLS12:
			return '2'
		case tls.VersionTLS13:
			return '3'
		}
		return 'x'
	case VerNo:
		return '-'
	default:
		return '?'
	}
}

// DefaultWarnDays es el umbral por defecto para marcar un certificado como
// proximo a vencer.
const DefaultWarnDays = 30

// Severity clasifica una fila. La distincion importa: un nombre que no
// coincide o un certificado vencido es un problema que hay que arreglar, y uno
// que vence en tres semanas es solo un aviso.
type Severity int

const (
	// SevOK: alcanzable, certificado valido y lejos de vencer.
	SevOK Severity = iota
	// SevWarning: certificado valido, pero vence dentro del umbral.
	SevWarning
	// SevProblem: inalcanzable, sin certificado, o certificado invalido
	// (vencido, autofirmado, nombre que no coincide, cadena no confiable).
	SevProblem
)

func (s Severity) String() string {
	switch s {
	case SevWarning:
		return "por vencer"
	case SevProblem:
		return "problema"
	default:
		return "ok"
	}
}
