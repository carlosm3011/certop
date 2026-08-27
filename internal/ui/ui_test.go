package ui

import (
	"context"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/gdamore/tcell/v2"

	"github.com/lacniclabs/certop/internal/inventory"
	"github.com/lacniclabs/certop/internal/probe"
)

func res(group, host, port string, days int, hasCert bool) probe.Result {
	r := probe.Result{
		Target:   inventory.Target{Group: group, Host: host, Port: port},
		DaysLeft: days,
	}
	if hasCert {
		r.TCP = probe.TCPOK
		r.CertStatus = probe.CertOK
		// Leaf no nulo para que HasCert sea verdadero.
		r.Leaf = leafStub()
	}
	return r
}

func TestSortOrder(t *testing.T) {
	results := []probe.Result{
		res("zeta", "b.example", "443", 90, true),
		res("alpha", "c.example", "443", 5, true),
		res("alpha", "a.example", "443", 40, true),
		res("email", "d.example", "993", 0, false), // inalcanzable
	}

	byGroup := sortOrder(results, sortByGroup)
	if got := results[byGroup[0]].Group; got != "alpha" {
		t.Errorf("primer grupo = %q, want alpha", got)
	}
	// Dentro del grupo, por host.
	if got := results[byGroup[0]].Host; got != "a.example" {
		t.Errorf("primer host de alpha = %q, want a.example", got)
	}
	if got := results[byGroup[3]].Group; got != "zeta" {
		t.Errorf("ultimo grupo = %q, want zeta", got)
	}

	byHost := sortOrder(results, sortByHost)
	want := []string{"a.example", "b.example", "c.example", "d.example"}
	for i, w := range want {
		if got := results[byHost[i]].Host; got != w {
			t.Errorf("byHost[%d] = %q, want %q", i, got, w)
		}
	}

	// Por expiracion: lo inalcanzable primero, despues por dias ascendentes.
	byExpiry := sortOrder(results, sortByExpiry)
	if results[byExpiry[0]].HasCert() {
		t.Error("el destino inalcanzable deberia ir primero")
	}
	if got := results[byExpiry[1]].DaysLeft; got != 5 {
		t.Errorf("segundo por expiracion = %dd, want 5d", got)
	}
	if got := results[byExpiry[3]].DaysLeft; got != 90 {
		t.Errorf("ultimo por expiracion = %dd, want 90d", got)
	}
}

func TestLayoutFitsWidth(t *testing.T) {
	results := []probe.Result{res("frontends", "rpki-fe-1.lacnic.net", "443", 45, true)}
	a := &App{}
	for _, width := range []int{80, 100, 140, 200} {
		c := a.layout(width, results)
		total := c.group + c.host + c.port + c.tcp + c.expiry + c.tlsCol + c.status + c.issuer + 7
		if total > width {
			t.Errorf("ancho %d: las columnas suman %d", width, total)
		}
	}
	// En una terminal angosta el emisor se reduce a cero, no a negativo.
	if c := a.layout(40, results); c.issuer != 0 {
		t.Errorf("emisor = %d, want 0", c.issuer)
	}
}

func TestCountWarn(t *testing.T) {
	results := []probe.Result{
		res("a", "sano", "443", 90, true),
		res("a", "porVencer", "443", 10, true),
		res("a", "caido", "443", 0, false),
	}
	filled := []bool{true, true, true}
	if got := countWarn(results, filled); got != 2 {
		t.Errorf("countWarn = %d, want 2", got)
	}
	// Lo que todavia no se chequeo no cuenta como problema.
	if got := countWarn(results, []bool{true, false, false}); got != 0 {
		t.Errorf("countWarn sin datos = %d, want 0", got)
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
		targets[i] = inventory.Target{Group: "g", Host: host, Port: port, Addr: addr}
	}

	a := newApp(screen, probe.New(time.Second, 4, false), targets, time.Second)

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
	if got := countWarn(a.results, a.filled); got != len(targets) {
		t.Errorf("countWarn = %d, want %d (todos inalcanzables)", got, len(targets))
	}
}
