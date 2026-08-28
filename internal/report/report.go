// Package report serializa los resultados del chequeo en los formatos de
// salida del modo --once y calcula el exit code.
package report

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"strconv"
	"text/tabwriter"
	"time"

	"github.com/lacniclabs/certop/internal/probe"
)

// Formatos de salida validos.
const (
	FormatCSV   = "csv"
	FormatTable = "table"
	FormatJSON  = "json"
)

// Formats son los formatos aceptados por --format.
var Formats = []string{FormatCSV, FormatTable, FormatJSON}

// Write serializa los resultados en el formato pedido.
func Write(w io.Writer, results []probe.Result, format string) error {
	switch format {
	case FormatCSV:
		return WriteCSV(w, results)
	case FormatTable:
		return WriteTable(w, results)
	case FormatJSON:
		return WriteJSON(w, results)
	default:
		return fmt.Errorf("formato desconocido %q (validos: %v)", format, Formats)
	}
}

var csvHeader = []string{
	"grupo", "host", "puerto", "af", "ip", "tcp", "expira_utc", "dias_restantes",
	"emisor", "estado_cert", "tls_negociada", "cipher", "clave", "firma",
	"tls10", "tls11", "tls12", "tls13", "starttls",
}

// WriteCSV es la salida por defecto de --once. La matriz de versiones se
// aplana en cuatro columnas.
func WriteCSV(w io.Writer, results []probe.Result) error {
	cw := csv.NewWriter(w)
	if err := cw.Write(csvHeader); err != nil {
		return err
	}
	for _, r := range results {
		row := []string{
			r.Group, r.Host, r.Port, r.AFText(), r.IPText(), r.TCP.String(),
			expiryUTC(r), daysField(r), r.Issuer, r.CertStatus.String(),
			r.NegVersionName(), r.NegCipherName(), r.KeyType, r.SigAlg,
		}
		for _, v := range probe.Versions {
			row = append(row, verState(r, v))
		}
		row = append(row, r.StartTLS)
		if err := cw.Write(row); err != nil {
			return err
		}
	}
	cw.Flush()
	return cw.Error()
}

// WriteTable escribe una tabla alineada legible.
func WriteTable(w io.Writer, results []probe.Result) error {
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	if _, err := fmt.Fprintln(tw, "GRUPO\tHOST\tAF\tIP\tPUERTO\tTCP\tEXPIRA\tTLS\tEMISOR\tESTADO"); err != nil {
		return err
	}
	for _, r := range results {
		if _, err := fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n",
			r.Group, r.Host, r.AFText(), r.IPText(), r.Port, r.TCP, r.ExpiryText(),
			r.TLSDigits(), dash(r.Issuer), r.CertStatus); err != nil {
			return err
		}
	}
	if err := tw.Flush(); err != nil {
		return err
	}
	_, err := fmt.Fprintf(w, "\n%s\n", Legend)
	return err
}

// Legend explica la columna compacta de versiones TLS.
const Legend = "tls: posiciones 1.0/1.1/1.2/1.3 - digito = aceptada, '-' = rechazada, '?' = sin determinar"

type jsonResult struct {
	Group      string         `json:"grupo"`
	Host       string         `json:"host"`
	Port       string         `json:"puerto"`
	Expect     string         `json:"expect,omitempty"`
	StartTLS   string         `json:"starttls,omitempty"`
	AF         int            `json:"af"`
	IP         string         `json:"ip"`
	TCP        string         `json:"tcp"`
	Expires    *time.Time     `json:"expira_utc"`
	DaysLeft   *int           `json:"dias_restantes"`
	Issuer     string         `json:"emisor"`
	CertStatus string         `json:"estado_cert"`
	Negotiated jsonNegotiated `json:"negociado"`
	TLS        map[string]any `json:"tls"`
	CheckedAt  time.Time      `json:"chequeado"`
	Error      string         `json:"error,omitempty"`
}

type jsonNegotiated struct {
	Version string `json:"version,omitempty"`
	Cipher  string `json:"cipher,omitempty"`
	Key     string `json:"clave,omitempty"`
	SigAlg  string `json:"firma,omitempty"`
}

// WriteJSON escribe los resultados como un arreglo JSON, con la matriz de
// versiones anidada.
func WriteJSON(w io.Writer, results []probe.Result) error {
	out := make([]jsonResult, 0, len(results))
	for _, r := range results {
		jr := jsonResult{
			Group:      r.Group,
			Host:       r.Host,
			Port:       r.Port,
			Expect:     r.Expect,
			StartTLS:   r.StartTLS,
			AF:         r.AF,
			IP:         r.IPText(),
			TCP:        r.TCP.String(),
			Issuer:     r.Issuer,
			CertStatus: r.CertStatus.String(),
			Negotiated: jsonNegotiated{
				Version: r.NegVersionName(),
				Cipher:  r.NegCipherName(),
				Key:     r.KeyType,
				SigAlg:  r.SigAlg,
			},
			TLS:       make(map[string]any, len(probe.Versions)),
			CheckedAt: r.CheckedAt,
		}
		if r.HasCert() {
			expires := r.NotAfter.UTC()
			days := r.DaysLeft
			jr.Expires = &expires
			jr.DaysLeft = &days
		}
		for _, v := range probe.Versions {
			name := probe.VersionName(v)
			switch r.Versions[v] {
			case probe.VerYes:
				jr.TLS[name] = true
			case probe.VerNo:
				jr.TLS[name] = false
			default:
				jr.TLS[name] = nil
			}
		}
		if r.Err != nil {
			jr.Error = r.Err.Error()
		}
		out = append(out, jr)
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(out)
}

// Exit codes.
const (
	ExitOK    = 0
	ExitUsage = 1
	ExitWarn  = 2
)

// ExitCode devuelve ExitWarn si algun destino es inalcanzable o su certificado
// expira dentro de warnDays. warnDays negativo desactiva el chequeo.
func ExitCode(results []probe.Result, warnDays int) int {
	if warnDays < 0 {
		return ExitOK
	}
	for _, r := range results {
		if !r.TCP.OK() || !r.HasCert() {
			return ExitWarn
		}
		if r.DaysLeft < warnDays {
			return ExitWarn
		}
	}
	return ExitOK
}

func expiryUTC(r probe.Result) string {
	if !r.HasCert() {
		return ""
	}
	return r.NotAfter.UTC().Format(time.RFC3339)
}

func daysField(r probe.Result) string {
	if !r.HasCert() {
		return ""
	}
	return strconv.Itoa(r.DaysLeft)
}

func verState(r probe.Result, v uint16) string {
	if r.Versions == nil {
		return probe.VerUnknown.String()
	}
	return r.Versions[v].String()
}

func dash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}
