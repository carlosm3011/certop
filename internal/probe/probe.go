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
	"slices"
	"strconv"
	"sync"
	"time"

	"github.com/carlosm3011/certop/internal/inventory"
)

// Result es el estado completo de un destino en un instante dado.
type Result struct {
	inventory.Target

	// IP es la direccion concreta que se chequeo; AF es 4 o 6, o 0 si no se
	// llego a resolver el nombre.
	IP net.IP
	AF int

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

// Severity clasifica la fila con el umbral de dias dado. Un umbral negativo
// desactiva el aviso por vencimiento, pero no los problemas.
func (r Result) Severity(warnDays int) Severity {
	if !r.TCP.OK() || !r.HasCert() || !r.CertStatus.OK() {
		return SevProblem
	}
	if warnDays >= 0 && r.DaysLeft < warnDays {
		return SevWarning
	}
	return SevOK
}

// Key identifica la fila. Un nombre se expande en una fila por direccion, asi
// que el indice en el inventario ya no alcanza como identidad.
func (r Result) Key() string {
	return r.Group + "\x00" + r.Host + "\x00" + r.Port + "\x00" + r.IPText()
}

// IPText es la direccion chequeada, o "-" si no se resolvio.
func (r Result) IPText() string {
	if r.IP == nil {
		return "-"
	}
	return r.IP.String()
}

// AFText es la familia de direcciones como se muestra en la columna AF.
func (r Result) AFText() string {
	if r.AF == 0 {
		return "-"
	}
	return strconv.Itoa(r.AF)
}

// DialAddr es la direccion a la que se conecta: siempre la IP concreta, nunca
// el nombre, para chequear cada registro por separado.
func (r Result) DialAddr() string {
	return net.JoinHostPort(r.IP.String(), r.Port)
}

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

	resolver *net.Resolver

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
		resolver:    net.DefaultResolver,
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

// Run resuelve cada destino, chequea todas sus direcciones concurrentemente y
// devuelve las filas en orden determinista (grupo, host, puerto, familia, IP).
// Si onResult no es nil se invoca por cada fila a medida que termina; puede
// llamarse desde varias goroutines a la vez.
//
// Un nombre produce una fila por cada registro A y AAAA: un config actualizado
// en una familia y no en la otra es justamente lo que se busca detectar.
func (c *Checker) Run(ctx context.Context, targets []inventory.Target, onResult func(Result)) []Result {
	units := c.expand(ctx, targets)

	results := make([]Result, len(units))
	sem := make(chan struct{}, c.Workers)
	var wg sync.WaitGroup

	for i, u := range units {
		if u.failed.TCP != TCPUnknown {
			// La resolucion ya fallo: la fila se reporta tal cual.
			results[i] = u.failed
			if onResult != nil {
				onResult(u.failed)
			}
			continue
		}
		wg.Add(1)
		go func(i int, u unit) {
			defer wg.Done()
			select {
			case sem <- struct{}{}:
				defer func() { <-sem }()
			case <-ctx.Done():
				results[i] = Result{Target: u.target, IP: u.ip, AF: afOf(u.ip), CheckedAt: time.Now(), Err: ctx.Err()}
				return
			}
			r := c.check(ctx, u.target, u.ip)
			results[i] = r
			if onResult != nil {
				onResult(r)
			}
		}(i, u)
	}
	wg.Wait()
	return results
}

// unit es una fila a chequear: un destino mas una direccion concreta. Si la
// resolucion fallo, failed trae la fila ya armada con el error.
type unit struct {
	target inventory.Target
	ip     net.IP
	failed Result
}

// expand resuelve los nombres del inventario en filas por direccion. Las
// direcciones se ordenan (v4 antes que v6, y por bytes dentro de la familia)
// porque el DNS rota el orden entre consultas y sin esto las filas saltarian de
// lugar en cada refresco.
func (c *Checker) expand(ctx context.Context, targets []inventory.Target) []unit {
	// Un mismo nombre puede aparecer varias veces en el inventario, con
	// puertos distintos: se resuelve una sola vez por pasada.
	type lookup struct {
		ips []net.IP
		err error
	}
	seen := make(map[string]lookup, len(targets))

	var units []unit
	for _, t := range targets {
		got, ok := seen[t.Host]
		if !ok {
			got.ips, got.err = c.resolve(ctx, t.Host)
			seen[t.Host] = got
		}
		if got.err != nil {
			units = append(units, unit{target: t, failed: Result{
				Target:    t,
				TCP:       TCPDNS,
				CheckedAt: time.Now(),
				Err:       got.err,
			}})
			continue
		}
		for _, ip := range got.ips {
			units = append(units, unit{target: t, ip: ip})
		}
	}
	return units
}

// resolve devuelve las direcciones del host, ordenadas de forma estable. Un
// literal IP se usa tal cual, sin consultar al DNS.
func (c *Checker) resolve(ctx context.Context, host string) ([]net.IP, error) {
	if ip := net.ParseIP(host); ip != nil {
		return []net.IP{ip}, nil
	}
	ctx, cancel := context.WithTimeout(ctx, c.Timeout)
	defer cancel()

	ips, err := c.resolver.LookupIP(ctx, "ip", host)
	if err != nil {
		return nil, err
	}
	if len(ips) == 0 {
		return nil, fmt.Errorf("el nombre %q no resolvio a ninguna direccion", host)
	}
	slices.SortFunc(ips, func(a, b net.IP) int {
		if d := afOf(a) - afOf(b); d != 0 {
			return d
		}
		return bytes.Compare(a, b)
	})
	return ips, nil
}

// afOf devuelve 4 o 6 segun la familia de la direccion.
func afOf(ip net.IP) int {
	if ip == nil {
		return 0
	}
	if ip.To4() != nil {
		return 4
	}
	return 6
}

// Check chequea un destino resolviendolo primero; devuelve la fila de la
// primera direccion. Pensado para pruebas y para chequeos puntuales: el camino
// normal es Run, que expande todas las direcciones.
func (c *Checker) Check(ctx context.Context, t inventory.Target) Result {
	ips, err := c.resolve(ctx, t.Host)
	if err != nil {
		return Result{Target: t, TCP: TCPDNS, CheckedAt: time.Now(), Err: err}
	}
	return c.check(ctx, t, ips[0])
}

// check chequea una direccion concreta: socket TCP, certificado y matriz de
// versiones.
func (c *Checker) check(ctx context.Context, t inventory.Target, ip net.IP) Result {
	r := Result{Target: t, IP: ip, AF: afOf(ip), CheckedAt: time.Now()}

	conn, err := c.dial(ctx, r.DialAddr())
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
		if errors.Is(err, errNoStartTLS) {
			r.CertStatus = CertNoStartTLS
		}
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
		r.CertStatus = classifyCert(leaf, state.PeerCertificates, t.VerifyName(), r.CheckedAt)
	} else {
		r.CertStatus = CertError
		r.Err = errors.New("el servidor no presento certificado")
	}

	r.Versions, r.ProbedAt = c.versionMatrix(ctx, t, ip)
	return r
}

// versionMatrix devuelve la matriz de versiones, sondeando solo si hace falta.
func (c *Checker) versionMatrix(ctx context.Context, t inventory.Target, ip net.IP) (map[uint16]VerState, time.Time) {
	// La clave incluye la direccion y el nombre verificado: dos nodos detras
	// del mismo CNAME pueden tener configuracion distinta, que es justamente
	// lo que se quiere detectar.
	key := net.JoinHostPort(ip.String(), t.Port) + "|" + t.VerifyName() + "|" + t.StartTLS
	if !c.ProbeAlways {
		c.mu.Lock()
		hit, ok := c.cache[key]
		c.mu.Unlock()
		if ok {
			return hit.versions, hit.probedAt
		}
	}

	versions := make(map[uint16]VerState, len(Versions))
	for _, v := range Versions {
		versions[v] = c.probeVersion(ctx, t, ip, v)
	}
	probedAt := time.Now()

	c.mu.Lock()
	c.cache[key] = cachedVersions{versions: versions, probedAt: probedAt}
	c.mu.Unlock()
	return versions, probedAt
}

// probeVersion intenta un handshake forzando una unica version de TLS.
func (c *Checker) probeVersion(ctx context.Context, t inventory.Target, ip net.IP, v uint16) VerState {
	conn, err := c.dial(ctx, net.JoinHostPort(ip.String(), t.Port))
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

func (c *Checker) dial(ctx context.Context, addr string) (net.Conn, error) {
	d := net.Dialer{Timeout: c.Timeout}
	return d.DialContext(ctx, "tcp", addr)
}

func (c *Checker) handshake(ctx context.Context, conn net.Conn, t inventory.Target, min, max uint16) (tls.ConnectionState, error) {
	// El deadline cubre el preambulo en claro ademas del handshake: para un
	// destino STARTTLS, --timeout es el presupuesto de la sesion entera.
	if err := conn.SetDeadline(time.Now().Add(c.Timeout)); err != nil {
		return tls.ConnectionState{}, err
	}
	if t.StartTLS != "" {
		if err := startTLS(conn, t.StartTLS); err != nil {
			return tls.ConnectionState{}, err
		}
	}
	tc := tls.Client(conn, tlsConfig(t.VerifyName(), min, max))
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
