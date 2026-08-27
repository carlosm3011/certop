// Package probe chequea el estado TLS de una lista de destinos: alcanzabilidad
// TCP, certificado, y que versiones de TLS acepta cada servidor.
package probe

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"math"
	"net"
	"sync"
	"time"

	"github.com/lacniclabs/certop/internal/inventory"
)

// Result es el estado completo de un destino en un instante dado.
type Result struct {
	inventory.Target

	TCP TCPState

	Leaf     *x509.Certificate
	NotAfter time.Time
	// DaysLeft es negativo si el certificado ya expiro.
	DaysLeft   int
	Issuer     string
	CertStatus CertStatus

	NegVersion uint16
	NegCipher  uint16
	KeyType    string
	SigAlg     string

	// Versions es la matriz de versiones aceptadas. Puede venir de la cache.
	Versions map[uint16]VerState
	ProbedAt time.Time

	CheckedAt time.Time
	Err       error
}

// HasCert indica si se obtuvo el certificado hoja.
func (r Result) HasCert() bool { return r.Leaf != nil }

// TLSDigits devuelve la representacion compacta de cuatro caracteres de la
// matriz de versiones, p.ej. "--23" (1.0 y 1.1 rechazadas, 1.2 y 1.3
// aceptadas).
func (r Result) TLSDigits() string {
	out := make([]rune, 0, len(Versions))
	for _, v := range Versions {
		state := VerUnknown
		if r.Versions != nil {
			state = r.Versions[v]
		}
		out = append(out, versionDigit(v, state))
	}
	return string(out)
}

// ExpiryText es la expiracion en dias, lista para mostrar.
func (r Result) ExpiryText() string {
	if !r.HasCert() {
		return "-"
	}
	return fmt.Sprintf("%dd", r.DaysLeft)
}

// NegVersionName es el nombre de la version negociada.
func (r Result) NegVersionName() string {
	if r.NegVersion == 0 {
		return ""
	}
	return VersionName(r.NegVersion)
}

// NegCipherName es el nombre del cipher suite negociado.
func (r Result) NegCipherName() string {
	if r.NegCipher == 0 {
		return ""
	}
	return tls.CipherSuiteName(r.NegCipher)
}

// Checker ejecuta los chequeos con un pool acotado de workers y cachea la
// matriz de versiones, que es cara (~5 handshakes por destino).
type Checker struct {
	Timeout     time.Duration
	Workers     int
	ProbeAlways bool

	mu    sync.Mutex
	cache map[string]cachedVersions
}

type cachedVersions struct {
	versions map[uint16]VerState
	probedAt time.Time
}

// New construye un Checker. Valores no positivos toman el default.
func New(timeout time.Duration, workers int, probeAlways bool) *Checker {
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	if workers <= 0 {
		workers = 32
	}
	return &Checker{
		Timeout:     timeout,
		Workers:     workers,
		ProbeAlways: probeAlways,
		cache:       make(map[string]cachedVersions),
	}
}

// InvalidateVersions descarta la matriz cacheada, forzando un re-sondeo en el
// proximo ciclo.
func (c *Checker) InvalidateVersions() {
	c.mu.Lock()
	c.cache = make(map[string]cachedVersions)
	c.mu.Unlock()
}

// Run chequea todos los destinos concurrentemente y devuelve los resultados en
// el mismo orden que targets. Si onResult no es nil se invoca por cada destino
// a medida que termina, con el indice correspondiente; puede llamarse desde
// varias goroutines a la vez.
func (c *Checker) Run(ctx context.Context, targets []inventory.Target, onResult func(int, Result)) []Result {
	results := make([]Result, len(targets))
	sem := make(chan struct{}, c.Workers)
	var wg sync.WaitGroup

	for i, t := range targets {
		wg.Add(1)
		go func(i int, t inventory.Target) {
			defer wg.Done()
			select {
			case sem <- struct{}{}:
				defer func() { <-sem }()
			case <-ctx.Done():
				results[i] = Result{Target: t, CheckedAt: time.Now(), Err: ctx.Err()}
				return
			}
			r := c.Check(ctx, t)
			results[i] = r
			if onResult != nil {
				onResult(i, r)
			}
		}(i, t)
	}
	wg.Wait()
	return results
}

// Check chequea un unico destino: socket TCP, certificado y matriz de
// versiones.
func (c *Checker) Check(ctx context.Context, t inventory.Target) Result {
	r := Result{Target: t, CheckedAt: time.Now()}

	conn, err := c.dial(ctx, t)
	if err != nil {
		r.TCP = classifyDial(err)
		r.Err = err
		return r
	}
	r.TCP = TCPOK

	state, err := c.handshake(ctx, conn, t, 0, 0)
	conn.Close()
	if err != nil {
		r.CertStatus = CertError
		r.Err = err
		return r
	}

	r.NegVersion = state.Version
	r.NegCipher = state.CipherSuite
	if len(state.PeerCertificates) > 0 {
		leaf := state.PeerCertificates[0]
		r.Leaf = leaf
		r.NotAfter = leaf.NotAfter
		r.DaysLeft = daysLeft(leaf.NotAfter, r.CheckedAt)
		r.Issuer = issuerName(leaf)
		r.KeyType = keyType(leaf)
		r.SigAlg = leaf.SignatureAlgorithm.String()
		r.CertStatus = classifyCert(leaf, state.PeerCertificates, t.Host, r.CheckedAt)
	} else {
		r.CertStatus = CertError
		r.Err = errors.New("el servidor no presento certificado")
	}

	r.Versions, r.ProbedAt = c.versionMatrix(ctx, t)
	return r
}

// versionMatrix devuelve la matriz de versiones, sondeando solo si hace falta.
func (c *Checker) versionMatrix(ctx context.Context, t inventory.Target) (map[uint16]VerState, time.Time) {
	if !c.ProbeAlways {
		c.mu.Lock()
		hit, ok := c.cache[t.Addr]
		c.mu.Unlock()
		if ok {
			return hit.versions, hit.probedAt
		}
	}

	versions := make(map[uint16]VerState, len(Versions))
	for _, v := range Versions {
		versions[v] = c.probeVersion(ctx, t, v)
	}
	probedAt := time.Now()

	c.mu.Lock()
	c.cache[t.Addr] = cachedVersions{versions: versions, probedAt: probedAt}
	c.mu.Unlock()
	return versions, probedAt
}

// probeVersion intenta un handshake forzando una unica version de TLS.
func (c *Checker) probeVersion(ctx context.Context, t inventory.Target, v uint16) VerState {
	conn, err := c.dial(ctx, t)
	if err != nil {
		// Un fallo de red no dice nada sobre la version soportada.
		return VerUnknown
	}
	defer conn.Close()

	if _, err := c.handshake(ctx, conn, t, v, v); err != nil {
		return versionVerdict(err)
	}
	return VerYes
}

func (c *Checker) dial(ctx context.Context, t inventory.Target) (net.Conn, error) {
	d := net.Dialer{Timeout: c.Timeout}
	return d.DialContext(ctx, "tcp", t.Addr)
}

func (c *Checker) handshake(ctx context.Context, conn net.Conn, t inventory.Target, min, max uint16) (tls.ConnectionState, error) {
	if err := conn.SetDeadline(time.Now().Add(c.Timeout)); err != nil {
		return tls.ConnectionState{}, err
	}
	tc := tls.Client(conn, tlsConfig(t.Host, min, max))
	if err := tc.HandshakeContext(ctx); err != nil {
		return tls.ConnectionState{}, err
	}
	return tc.ConnectionState(), nil
}

// tlsConfig arma la configuracion del cliente. La verificacion se desactiva a
// proposito: el certificado hoja se obtiene siempre y se valida aparte, de modo
// que un host con certificado invalido igual reporta expiracion y emisor.
func tlsConfig(host string, min, max uint16) *tls.Config {
	cfg := &tls.Config{
		InsecureSkipVerify: true, //nolint:gosec // validacion explicita en classifyCert
		MinVersion:         tls.VersionTLS10,
		MaxVersion:         tls.VersionTLS13,
		// Se ofrecen todas las suites que implementa el paquete, incluidas las
		// obsoletas: la lista por defecto de Go omite RSA-kex y 3DES, y sin
		// ellas un servidor que solo habla TLS 1.0/1.1 se reportaria como si
		// rechazara la version. Ignorado para TLS 1.3.
		CipherSuites: allCipherSuites(),
	}
	// SNI solo aplica a nombres, no a literales IP.
	if net.ParseIP(host) == nil {
		cfg.ServerName = host
	}
	if min != 0 {
		cfg.MinVersion = min
	}
	if max != 0 {
		cfg.MaxVersion = max
	}
	return cfg
}

var allCipherSuites = sync.OnceValue(func() []uint16 {
	suites := tls.CipherSuites()
	ids := make([]uint16, 0, len(suites)+len(tls.InsecureCipherSuites()))
	for _, s := range suites {
		ids = append(ids, s.ID)
	}
	for _, s := range tls.InsecureCipherSuites() {
		ids = append(ids, s.ID)
	}
	return ids
})

// classifyDial traduce el error de conexion a un TCPState.
func classifyDial(err error) TCPState {
	var dnsErr *net.DNSError
	if errors.As(err, &dnsErr) {
		return TCPDNS
	}
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return TCPTimeout
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return TCPTimeout
	}
	if isRefused(err) {
		return TCPRefused
	}
	return TCPError
}

// classifyCert valida el certificado y traduce el resultado a un CertStatus.
//
// La expiracion se chequea primero a proposito: un certificado vencido tambien
// falla la verificacion de cadena, y "EXPIRADO" es la etiqueta util.
func classifyCert(leaf *x509.Certificate, chain []*x509.Certificate, host string, now time.Time) CertStatus {
	if now.After(leaf.NotAfter) || now.Before(leaf.NotBefore) {
		return CertExpired
	}
	if err := leaf.VerifyHostname(host); err != nil {
		return CertHostnameMismatch
	}

	intermediates := x509.NewCertPool()
	for _, c := range chain[1:] {
		intermediates.AddCert(c)
	}
	if _, err := leaf.Verify(x509.VerifyOptions{
		Intermediates: intermediates,
		CurrentTime:   now,
	}); err != nil {
		// No se clasifica por tipo de error: con Roots nil, macOS delega en el
		// verificador del sistema y devuelve errores distintos a los de Linux.
		// La distincion que importa se decide mirando el certificado.
		if isSelfSigned(leaf) {
			return CertSelfSigned
		}
		return CertIncompleteChain
	}
	return CertOK
}

func isSelfSigned(leaf *x509.Certificate) bool {
	if !bytes.Equal(leaf.RawIssuer, leaf.RawSubject) {
		return false
	}
	// CheckSignatureFrom no sirve aca: exige que el firmante sea CA, y un
	// certificado de servidor autofirmado normalmente no lo es.
	return leaf.CheckSignature(leaf.SignatureAlgorithm, leaf.RawTBSCertificate, leaf.Signature) == nil
}

// versionVerdict interpreta el fallo de un handshake dirigido a una version.
// Solo los fallos de red dejan la respuesta como desconocida; cualquier rechazo
// del servidor (alerta TLS, conexion cerrada) cuenta como version no soportada.
func versionVerdict(err error) VerState {
	if err == nil {
		return VerYes
	}
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
		return VerUnknown
	}
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return VerUnknown
	}
	return VerNo
}

func daysLeft(notAfter, now time.Time) int {
	return int(math.Floor(notAfter.Sub(now).Hours() / 24))
}

func issuerName(leaf *x509.Certificate) string {
	if cn := leaf.Issuer.CommonName; cn != "" {
		return cn
	}
	if org := leaf.Issuer.Organization; len(org) > 0 {
		return org[0]
	}
	return leaf.Issuer.String()
}

func keyType(leaf *x509.Certificate) string {
	switch pub := leaf.PublicKey.(type) {
	case *rsa.PublicKey:
		return fmt.Sprintf("RSA %d", pub.N.BitLen())
	case *ecdsa.PublicKey:
		return "ECDSA " + pub.Curve.Params().Name
	case ed25519.PublicKey:
		return "Ed25519"
	default:
		return leaf.PublicKeyAlgorithm.String()
	}
}
