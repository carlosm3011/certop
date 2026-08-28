package ui

import (
	"context"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/gdamore/tcell/v2"

	"github.com/carlosm3011/certop/internal/inventory"
	"github.com/carlosm3011/certop/internal/probe"
)

func res(group, host, port string, days int, hasCert bool) probe.Result {
	r := probe.Result{
		Target:   inventory.Target{Group: group, Host: host, Port: port},
		DaysLeft: days,
		IP:       net.ParseIP("192.0.2.1"),
		AF:       4,
	}
	if hasCert {
		r.TCP = probe.TCPOK
		r.CertStatus = probe.CertOK
		// Leaf no nulo para que HasCert sea verdadero.
		r.Leaf = leafStub()
	}
	return r
}

func rowsOf(results ...probe.Result) []row {
	out := make([]row, len(results))
	for i, r := range results {
		out[i] = row{result: r, fresh: true}
	}
	return out
}

func TestSortRows(t *testing.T) {
	base := []probe.Result{
		res("zeta", "b.example", "443", 90, true),
		res("alpha", "c.example", "443", 5, true),
		res("alpha", "a.example", "443", 40, true),
		res("email", "d.example", "993", 0, false), // inalcanzable
	}

	byGroup := rowsOf(base...)
	sortRows(byGroup, sortByGroup)
	if got := byGroup[0].result.Group; got != "alpha" {
		t.Errorf("primer grupo = %q, want alpha", got)
	}
	if got := byGroup[0].result.Host; got != "a.example" {
		t.Errorf("primer host de alpha = %q, want a.example", got)
	}
	if got := byGroup[3].result.Group; got != "zeta" {
		t.Errorf("ultimo grupo = %q, want zeta", got)
	}

	byHost := rowsOf(base...)
	sortRows(byHost, sortByHost)
	want := []string{"a.example", "b.example", "c.example", "d.example"}
	for i, w := range want {
		if got := byHost[i].result.Host; got != w {
			t.Errorf("byHost[%d] = %q, want %q", i, got, w)
		}
	}

	byExpiry := rowsOf(base...)
	sortRows(byExpiry, sortByExpiry)
	if byExpiry[0].result.HasCert() {
		t.Error("el destino inalcanzable deberia ir primero")
	}
	if got := byExpiry[1].result.DaysLeft; got != 5 {
		t.Errorf("segundo por expiracion = %dd, want 5d", got)
	}
	if got := byExpiry[3].result.DaysLeft; got != 90 {
		t.Errorf("ultimo por expiracion = %dd, want 90d", got)
	}
}

// Las filas de un mismo host se agrupan y quedan en orden estable por familia.
func TestSortRowsGroupsAddressesOfSameHost(t *testing.T) {
	v6 := res("g", "dual.example", "443", 30, true)
	v6.IP, v6.AF = net.ParseIP("2001:db8::1"), 6
	v4 := res("g", "dual.example", "443", 30, true)
	otro := res("g", "aaa.example", "443", 30, true)

	for _, mode := range []int{sortByGroup, sortByHost, sortByExpiry} {
		rows := rowsOf(v6, otro, v4)
		sortRows(rows, mode)
		if rows[1].result.Host != "dual.example" || rows[2].result.Host != "dual.example" {
			t.Fatalf("modo %d: las filas del host dual no quedaron juntas: %+v", mode, rows)
		}
		if rows[1].result.AF != 4 || rows[2].result.AF != 6 {
			t.Errorf("modo %d: familias en orden %d, %d; want 4, 6", mode, rows[1].result.AF, rows[2].result.AF)
		}
	}
}

func TestLayoutFitsWidth(t *testing.T) {
	results := []probe.Result{res("frontends", "rpki-fe-1.lacnic.net", "443", 45, true)}
	a := &App{}
	for _, width := range []int{80, 100, 140, 200} {
		c := a.layout(width, results)
		total := c.group + c.host + c.af + c.ip + c.port + c.tcp + c.expiry + c.tlsCol + c.status + c.issuer + 9
		if total > width {
			t.Errorf("ancho %d: las columnas suman %d", width, total)
		}
	}
	// En una terminal angosta el emisor se reduce a cero, no a negativo, y la
	// IP se recorta antes de volverse negativa.
	c := a.layout(40, results)
	if c.issuer != 0 {
		t.Errorf("emisor = %d, want 0", c.issuer)
	}
	if c.ip < 0 {
		t.Errorf("ip = %d, want >= 0", c.ip)
	}
}

// Un nombre que no coincide es un problema; un certificado sano que vence en
// tres semanas es solo un aviso. No se cuentan juntos.
func TestCountsSeparatesProblemsFromWarnings(t *testing.T) {
	sano := res("a", "sano", "443", 90, true)
	porVencer := res("a", "porVencer", "443", 10, true)
	caido := res("a", "caido", "443", 0, false)
	mismatch := res("a", "mismatch", "443", 200, true)
	mismatch.CertStatus = probe.CertHostnameMismatch
	vencido := res("a", "vencido", "443", -3, true)
	vencido.CertStatus = probe.CertExpired
	selfSigned := res("a", "self", "443", 200, true)
	selfSigned.CertStatus = probe.CertSelfSigned

	rows := rowsOf(sano, porVencer, caido, mismatch, vencido, selfSigned)
	problems, warnings := counts(rows, 30)
	if problems != 4 {
		t.Errorf("problemas = %d, want 4 (caido, mismatch, vencido, self-signed)", problems)
	}
	if warnings != 1 {
		t.Errorf("avisos = %d, want 1 (solo el que vence en 10d)", warnings)
	}

	// El umbral mueve solo la categoria de aviso.
	problems, warnings = counts(rows, 5)
	if problems != 4 || warnings != 0 {
		t.Errorf("umbral 5: problemas=%d avisos=%d, want 4/0", problems, warnings)
	}
	// Con un umbral alto el de 90 dias tambien entra como aviso.
	problems, warnings = counts(rows, 120)
	if problems != 4 || warnings != 2 {
		t.Errorf("umbral 120: problemas=%d avisos=%d, want 4/2", problems, warnings)
	}

	// Lo que todavia no se chequeo no cuenta en ninguna categoria.
	for i := range rows {
		rows[i].fresh = false
	}
	if p, w := counts(rows, 30); p != 0 || w != 0 {
		t.Errorf("sin datos: problemas=%d avisos=%d, want 0/0", p, w)
	}
}

// El color sigue la severidad, no la mezcla de antes.
func TestRowStyleFollowsSeverity(t *testing.T) {
	mismatch := res("a", "mismatch", "443", 200, true)
	mismatch.CertStatus = probe.CertHostnameMismatch

	fg := func(r probe.Result) tcell.Color {
		f, _, _ := rowStyle(r, true, 30).Decompose()
		return f
	}
	if got := fg(mismatch); got != tcell.ColorRed {
		t.Errorf("nombre que no coincide = %v, want rojo", got)
	}
	if got := fg(res("a", "porVencer", "443", 10, true)); got != tcell.ColorYellow {
		t.Errorf("por vencer = %v, want amarillo", got)
	}
	if got := fg(res("a", "sano", "443", 200, true)); got != tcell.ColorGreen {
		t.Errorf("sano = %v, want verde", got)
	}
	if got := fg(res("a", "caido", "443", 0, false)); got != tcell.ColorRed {
		t.Errorf("caido = %v, want rojo", got)
	}
}

// Ejercita el dibujado contra los ciclos de chequeo concurrentes; corre con
// -race para detectar accesos sin proteger al estado compartido.
func TestDrawWhileChecking(t *testing.T) {
	screen := tcell.NewSimulationScreen("UTF-8")
	if err := screen.Init(); err != nil {
		t.Fatal(err)
	}
	defer screen.Fini()
	screen.SetSize(120, 24)

	// Un puerto cerrado en loopback: falla rapido y no toca la red externa.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	host, port, _ := net.SplitHostPort(addr)
	ln.Close()

	targets := make([]inventory.Target, 8)
	for i := range targets {
		targets[i] = inventory.Target{Group: string(rune('a' + i)), Host: host, Port: port, Addr: addr}
	}

	a := newApp(screen, probe.New(time.Second, 4, false), targets, time.Second, 30)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 3; i++ {
			a.startCycle(ctx)
			time.Sleep(20 * time.Millisecond)
		}
	}()
	wg.Add(1)
	go func() {
		defer wg.Done()
		deadline := time.Now().Add(400 * time.Millisecond)
		for time.Now().Before(deadline) {
			a.draw()
		}
	}()
	wg.Wait()

	// Esperar a que el ciclo en curso termine antes de cerrar la pantalla.
	for i := 0; i < 100; i++ {
		a.mu.Lock()
		running := a.running
		a.mu.Unlock()
		if !running {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}

	a.draw()

	a.mu.Lock()
	rows := make([]row, 0, len(a.rows))
	for _, r := range a.rows {
		rows = append(rows, r)
	}
	a.mu.Unlock()
	if got, _ := counts(rows, 30); got != len(targets) {
		t.Errorf("problemas = %d, want %d (todos inalcanzables)", got, len(targets))
	}
}

// Una fila que el DNS dejo de devolver se descarta al cerrar el ciclo, pero
// sigue visible mientras la pasada corre.
func TestPruneVanishedRows(t *testing.T) {
	screen := tcell.NewSimulationScreen("UTF-8")
	if err := screen.Init(); err != nil {
		t.Fatal(err)
	}
	defer screen.Fini()
	screen.SetSize(120, 24)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	host, port, _ := net.SplitHostPort(addr)
	ln.Close()

	tgt := inventory.Target{Group: "g", Host: host, Port: port, Addr: addr}
	a := newApp(screen, probe.New(time.Second, 4, false), []inventory.Target{tgt}, time.Second, 30)

	// Fila de una direccion que ya no se resuelve.
	stale := probe.Result{
		Target: inventory.Target{Group: "g", Host: host, Port: port},
		IP:     net.ParseIP("192.0.2.99"),
		AF:     4,
	}
	a.mu.Lock()
	a.rows[stale.Key()] = row{result: stale, fresh: true}
	before := len(a.rows)
	a.mu.Unlock()
	if before != 2 {
		t.Fatalf("preparacion: %d filas, want 2", before)
	}

	a.startCycle(context.Background())
	for i := 0; i < 100; i++ {
		a.mu.Lock()
		running := a.running
		a.mu.Unlock()
		if !running {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}

	a.mu.Lock()
	defer a.mu.Unlock()
	if _, ok := a.rows[stale.Key()]; ok {
		t.Error("la fila obsoleta sobrevivio al ciclo")
	}
	if len(a.rows) != 1 {
		t.Errorf("quedaron %d filas, want 1", len(a.rows))
	}
}

// Un destino cuyo nombre no resuelve produce una fila con IP "-", que es la
// misma clave que su placeholder: no hay que confundirla con uno y borrarla.
func TestDNSFailureRowSurvives(t *testing.T) {
	screen := tcell.NewSimulationScreen("UTF-8")
	if err := screen.Init(); err != nil {
		t.Fatal(err)
	}
	defer screen.Fini()
	screen.SetSize(120, 24)

	tgt := inventory.Target{Group: "g", Host: "no.existe.invalid", Port: "443", Addr: "no.existe.invalid:443"}
	a := newApp(screen, probe.New(time.Second, 2, false), []inventory.Target{tgt}, time.Second, 30)

	a.startCycle(context.Background())
	for i := 0; i < 100; i++ {
		a.mu.Lock()
		running := a.running
		a.mu.Unlock()
		if !running {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}

	a.mu.Lock()
	defer a.mu.Unlock()
	if len(a.rows) != 1 {
		t.Fatalf("got %d filas, want 1", len(a.rows))
	}
	for _, r := range a.rows {
		if !r.fresh {
			t.Error("la fila quedo como placeholder en vez de reportar el fallo de DNS")
		}
		if r.result.TCP != probe.TCPDNS {
			t.Errorf("TCP = %v, want dns", r.result.TCP)
		}
	}
}
